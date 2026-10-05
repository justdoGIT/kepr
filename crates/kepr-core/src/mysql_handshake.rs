//! MySQL handshake packets (T7.02): the server's greeting, the client's
//! response (and the SSLRequest prefix of it) and the auth switch.

use crate::mysql_wire::{caps, put_lenenc, take, take_lenenc, take_nul, text, MAX_PACKET};

/// Protocol::HandshakeV10, the server's first packet.
#[derive(Debug, Clone, PartialEq)]
pub struct Greeting {
    pub version: String,
    pub conn_id: u32,
    pub scramble: Vec<u8>,
    pub caps: u32,
    pub charset: u8,
    pub status: u16,
    /// Kept as sent: MariaDB puts extended capabilities here.
    pub reserved: [u8; 10],
    pub plugin: String,
}

impl Greeting {
    /// Only 4.1+ greetings with plugin auth (every server since 5.5).
    pub fn parse(p: &[u8]) -> Option<Self> {
        let mut b = p;
        if take(&mut b, 1)? != [10] {
            return None;
        }
        let version = text(take_nul(&mut b));
        let conn_id = u32::from_le_bytes(take(&mut b, 4)?.try_into().ok()?);
        let mut scramble = take(&mut b, 8)?.to_vec();
        take(&mut b, 1)?;
        let lo = u16::from_le_bytes(take(&mut b, 2)?.try_into().ok()?) as u32;
        let charset = take(&mut b, 1)?[0];
        let status = u16::from_le_bytes(take(&mut b, 2)?.try_into().ok()?);
        let hi = u16::from_le_bytes(take(&mut b, 2)?.try_into().ok()?) as u32;
        let caps = lo | hi << 16;
        let auth_len = take(&mut b, 1)?[0] as usize;
        let reserved: [u8; 10] = take(&mut b, 10)?.try_into().ok()?;
        let need = caps::PROTOCOL_41 | caps::SECURE_CONNECTION | caps::PLUGIN_AUTH;
        if caps & need != need {
            return None;
        }
        let part2 = take(&mut b, auth_len.saturating_sub(8).max(13))?;
        scramble.extend_from_slice(part2.strip_suffix(&[0]).unwrap_or(part2));
        let plugin = text(take_nul(&mut b));
        Some(Self {
            version,
            conn_id,
            scramble,
            caps,
            charset,
            status,
            reserved,
            plugin,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![10];
        out.extend_from_slice(self.version.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.conn_id.to_le_bytes());
        let (p1, p2) = self.scramble.split_at(self.scramble.len().min(8));
        out.extend_from_slice(p1);
        out.push(0);
        out.extend_from_slice(&(self.caps as u16).to_le_bytes());
        out.push(self.charset);
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&((self.caps >> 16) as u16).to_le_bytes());
        out.push((self.scramble.len() + 1) as u8);
        out.extend_from_slice(&self.reserved);
        let mut part2 = p2.to_vec();
        part2.resize(part2.len().max(12), 0);
        out.extend_from_slice(&part2);
        out.push(0);
        out.extend_from_slice(self.plugin.as_bytes());
        out.push(0);
        out
    }
}

/// Protocol::HandshakeResponse41, the client's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeResponse {
    pub caps: u32,
    pub max_packet: u32,
    pub charset: u8,
    /// Kept as sent: MariaDB puts extended capabilities here.
    pub filler: [u8; 23],
    pub user: String,
    pub auth: Vec<u8>,
    pub database: Option<String>,
    pub plugin: Option<String>,
}

impl HandshakeResponse {
    pub fn new(caps: u32, user: &str, auth: Vec<u8>, plugin: &str) -> Self {
        Self {
            caps: caps | caps::PROTOCOL_41 | caps::SECURE_CONNECTION | caps::PLUGIN_AUTH,
            max_packet: MAX_PACKET as u32,
            charset: 45, // utf8mb4_general_ci
            filler: [0; 23],
            user: user.into(),
            auth,
            database: None,
            plugin: Some(plugin.into()),
        }
    }

    /// The full response, or `None` (SSLRequest, pre-4.1, truncated).
    pub fn parse(p: &[u8]) -> Option<Self> {
        let mut b = p;
        let caps = u32::from_le_bytes(take(&mut b, 4)?.try_into().ok()?);
        if caps & caps::PROTOCOL_41 == 0 {
            return None;
        }
        let max_packet = u32::from_le_bytes(take(&mut b, 4)?.try_into().ok()?);
        let charset = take(&mut b, 1)?[0];
        let filler: [u8; 23] = take(&mut b, 23)?.try_into().ok()?;
        if b.is_empty() {
            return None; // an SSLRequest
        }
        let user = text(take_nul(&mut b));
        let auth = if caps & caps::PLUGIN_AUTH_LENENC != 0 {
            let n = take_lenenc(&mut b)? as usize;
            take(&mut b, n)?.to_vec()
        } else if caps & caps::SECURE_CONNECTION != 0 {
            let n = take(&mut b, 1)?[0] as usize;
            take(&mut b, n)?.to_vec()
        } else {
            take_nul(&mut b).to_vec()
        };
        let database = (caps & caps::CONNECT_WITH_DB != 0).then(|| text(take_nul(&mut b)));
        let plugin = (caps & caps::PLUGIN_AUTH != 0).then(|| text(take_nul(&mut b)));
        Some(Self {
            caps,
            max_packet,
            charset,
            filler,
            user,
            auth,
            database,
            plugin,
        })
    }

    /// The first 32 bytes, sent with CLIENT_SSL before the TLS handshake.
    pub fn ssl_request(&self) -> Vec<u8> {
        let mut out = (self.caps | caps::SSL).to_le_bytes().to_vec();
        out.extend_from_slice(&self.max_packet.to_le_bytes());
        out.push(self.charset);
        out.extend_from_slice(&self.filler);
        out
    }

    /// Encoded with `caps` as they are (connect attributes are not sent:
    /// callers clear CONNECT_ATTRS).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.ssl_request();
        out[..4].copy_from_slice(&self.caps.to_le_bytes());
        out.extend_from_slice(self.user.as_bytes());
        out.push(0);
        if self.caps & caps::PLUGIN_AUTH_LENENC != 0 {
            put_lenenc(&mut out, self.auth.len() as u64);
        } else {
            out.push(self.auth.len() as u8);
        }
        out.extend_from_slice(&self.auth);
        if self.caps & caps::CONNECT_WITH_DB != 0 {
            out.extend_from_slice(self.database.as_deref().unwrap_or_default().as_bytes());
            out.push(0);
        }
        if self.caps & caps::PLUGIN_AUTH != 0 {
            out.extend_from_slice(self.plugin.as_deref().unwrap_or_default().as_bytes());
            out.push(0);
        }
        if self.caps & caps::CONNECT_ATTRS != 0 {
            out.push(0); // no attributes
        }
        out
    }
}

/// AuthSwitchRequest asking the client to answer `plugin` with `nonce`.
pub fn auth_switch(plugin: &str, nonce: &[u8]) -> Vec<u8> {
    let mut out = vec![0xfe];
    out.extend_from_slice(plugin.as_bytes());
    out.push(0);
    out.extend_from_slice(nonce);
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mysql_wire::CACHING_SHA2;

    const NONCE: [u8; 20] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ];

    fn greeting() -> Greeting {
        Greeting {
            version: "8.0.36".into(),
            conn_id: 42,
            scramble: NONCE.to_vec(),
            caps: 0xffff_f7ff,
            charset: 255,
            status: 2,
            reserved: [0; 10],
            plugin: CACHING_SHA2.into(),
        }
    }

    #[test]
    fn greeting_round_trips() {
        let g = greeting();
        assert_eq!(Greeting::parse(&g.encode()), Some(g.clone()));
        let old = Greeting {
            caps: caps::PROTOCOL_41,
            ..g
        };
        assert!(
            Greeting::parse(&old.encode()).is_none(),
            "plugin auth needed"
        );
    }

    #[test]
    fn handshake_response_round_trips() {
        let mut r = HandshakeResponse::new(
            caps::CONNECT_WITH_DB | caps::PLUGIN_AUTH_LENENC,
            "app",
            vec![7; 32],
            CACHING_SHA2,
        );
        r.database = Some("prod".into());
        assert_eq!(HandshakeResponse::parse(&r.encode()), Some(r.clone()));
        r.caps &= !(caps::PLUGIN_AUTH_LENENC | caps::CONNECT_WITH_DB);
        r.database = None;
        assert_eq!(HandshakeResponse::parse(&r.encode()), Some(r.clone()));
        assert!(HandshakeResponse::parse(&r.ssl_request()).is_none());
        let attrs = HandshakeResponse {
            caps: r.caps | caps::CONNECT_ATTRS,
            ..r.clone()
        };
        assert_eq!(
            HandshakeResponse::parse(&attrs.encode()).unwrap().user,
            "app"
        );
    }
}
