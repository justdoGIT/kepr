// cli_gatex/mysql_login.rs — `kepr agent rotate-db` for MySQL logins
// (T7.04): log in through the gate's MySQL port with the route's
// placeholder (as a caching_sha2_password scramble, never in clear). As
// user `kepr_rotate` the gate first changes the password; an OK then means
// the server has the pending password. As anyone else, an OK means the
// current password still works (the `--abort` check).

use std::io::{Read, Write};

use kepr_core::mysql_wire::{
    self as wire, caps, Greeting, HandshakeResponse, CACHING_SHA2, ROTATE_USER,
};

fn read_packet(s: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).map_err(|e| e.to_string())?;
    let (len, _) = wire::header(h);
    if len > 1 << 20 {
        return Err("malformed reply from the gate".into());
    }
    let mut p = vec![0u8; len];
    s.read_exact(&mut p).map_err(|e| e.to_string())?;
    Ok(p)
}

fn refused(p: &[u8]) -> String {
    wire::parse_err(p).map_or_else(|| "the database refused".into(), |(_, m)| m)
}

/// Log in through the gate; Ok at the server's OK packet.
pub fn drive(s: &mut (impl Read + Write), placeholder: &str, rotate: bool) -> Result<(), String> {
    let g = read_packet(s)?;
    if g.first() == Some(&0xff) {
        return Err(refused(&g));
    }
    let g = Greeting::parse(&g).ok_or("unexpected greeting from the gate")?;
    let user = if rotate { ROTATE_USER } else { "kepr" };
    let auth = wire::sha2_scramble(placeholder.as_bytes(), &g.scramble);
    let r = HandshakeResponse::new(caps::DEPRECATE_EOF, user, auth, CACHING_SHA2);
    s.write_all(&wire::packet(1, &r.encode()))
        .map_err(|e| e.to_string())?;
    loop {
        let p = read_packet(s)?;
        match p.first() {
            Some(0x00) => return Ok(()),
            Some(0xff) => return Err(refused(&p)),
            // caching_sha2_password "fast auth succeeded"; the OK follows.
            Some(0x01) if p.get(1) == Some(&3) => {}
            _ => return Err("unexpected reply from the gate".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn greeting() -> Greeting {
        Greeting {
            version: "8.0.36".into(),
            conn_id: 1,
            scramble: b"abcdefghijklmnopqrst".to_vec(),
            caps: caps::PROTOCOL_41 | caps::SECURE_CONNECTION | caps::PLUGIN_AUTH,
            charset: 255,
            status: 2,
            reserved: [0; 10],
            plugin: CACHING_SHA2.into(),
        }
    }

    fn gate_says(replies: &[&[u8]]) -> Duplex {
        let mut input = wire::packet(0, &greeting().encode());
        for (i, r) in replies.iter().enumerate() {
            input.extend(wire::packet(2 + i as u8, r));
        }
        Duplex {
            input: Cursor::new(input),
            output: Vec::new(),
        }
    }

    #[test]
    fn logs_in_as_kepr_rotate_with_the_placeholder_scramble() {
        let mut d = gate_says(&[&[0x01, 0x03], &wire::ok_packet(2)]);
        drive(&mut d, "kepr-ph-1", true).unwrap();
        let (len, seq) = wire::header(d.output[..4].try_into().unwrap());
        assert_eq!((len + 4, seq), (d.output.len(), 1));
        let r = HandshakeResponse::parse(&d.output[4..]).unwrap();
        assert_eq!(r.user, ROTATE_USER);
        assert_eq!(r.plugin.as_deref(), Some(CACHING_SHA2));
        assert_eq!(
            r.auth,
            wire::sha2_scramble(b"kepr-ph-1", b"abcdefghijklmnopqrst")
        );
        assert!(
            !d.output.windows(9).any(|w| w == b"kepr-ph-1"),
            "placeholder never sent in clear"
        );

        let mut d = gate_says(&[&wire::ok_packet(2)]);
        drive(&mut d, "kepr-ph-1", false).unwrap();
        assert_eq!(
            HandshakeResponse::parse(&d.output[4..]).unwrap().user,
            "kepr"
        );
    }

    #[test]
    fn reports_the_gate_or_server_error() {
        let err = wire::err_packet(1045, "28000", "kepr: rotate: no rotation pending");
        let mut d = gate_says(&[&err]);
        assert_eq!(
            drive(&mut d, "x", true).unwrap_err(),
            "kepr: rotate: no rotation pending"
        );
        let mut d = gate_says(&[&[0xfe, b'x']]);
        assert!(drive(&mut d, "x", true).is_err());
    }
}
