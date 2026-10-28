//! Session-bound placeholders (T1.07).
//!
//! The agent only ever sees `kepr-ph-{session}-{slot}-{mac}`. It is
//! worthless outside this gate session: the MAC is keyed with a
//! per-session random key that never leaves the daemon and the gate.

use kepr_core::mac;

pub const PREFIX: &str = "kepr-ph-";
const MAC_HEX_LEN: usize = 16;

fn mac_for(session_key: &[u8; 32], session_id: &str, slot: u16) -> zeroize::Zeroizing<[u8; 32]> {
    mac::hmac_sha256(session_key, &[format!("{session_id}:{slot}").as_bytes()])
}

pub fn make(session_key: &[u8; 32], session_id: &str, slot: u16) -> String {
    let tag = mac_for(session_key, session_id, slot);
    let mac = hex::encode(&tag[..MAC_HEX_LEN / 2]);
    format!("{PREFIX}{session_id}-{slot:04x}-{mac}")
}

#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub session_id: String,
    pub slot: u16,
    pub mac: String,
}

fn is_lower_hex(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

pub fn parse(s: &str) -> Option<Parsed> {
    let rest = s.strip_prefix(PREFIX)?;
    let mut it = rest.split('-');
    let (session_id, slot, mac) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some()
        || session_id.len() != 16
        || slot.len() != 4
        || mac.len() != MAC_HEX_LEN
        || !is_lower_hex(session_id)
        || !is_lower_hex(slot)
        || !is_lower_hex(mac)
    {
        return None;
    }
    Some(Parsed {
        session_id: session_id.to_string(),
        slot: u16::from_str_radix(slot, 16).ok()?,
        mac: mac.to_string(),
    })
}

/// Constant-time MAC check.
pub fn verify(session_key: &[u8; 32], p: &Parsed) -> bool {
    let Ok(tag) = hex::decode(&p.mac) else {
        return false;
    };
    mac::hmac_sha256_verify(
        session_key,
        &[format!("{}:{}", p.session_id, p.slot).as_bytes()],
        &tag,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "0123456789abcdef";

    #[test]
    fn round_trip() {
        let k = [7u8; 32];
        let ph = make(&k, SID, 3);
        let p = parse(&ph).unwrap();
        assert_eq!(p.slot, 3);
        assert_eq!(p.session_id, SID);
        assert!(verify(&k, &p));
    }

    #[test]
    fn other_key_or_tampered_fails() {
        let ph = make(&[1u8; 32], SID, 0);
        assert!(!verify(&[2u8; 32], &parse(&ph).unwrap()));
        let mut chars: Vec<char> = ph.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let tampered: String = chars.into_iter().collect();
        assert!(!verify(&[1u8; 32], &parse(&tampered).unwrap()));
    }

    #[test]
    fn parse_rejects_non_placeholders() {
        for s in [
            "sk-ant-abc",
            "",
            "kepr-xx-0123456789abcdef-0000-0123456789abcdef",
            "kepr-ph-0123456789abcdef-zzzz-0123456789abcdef",
            "kepr-ph-0123456789abcdef-0000-0123456789abcdef-x",
        ] {
            assert!(parse(s).is_none(), "{s}");
        }
    }
}
