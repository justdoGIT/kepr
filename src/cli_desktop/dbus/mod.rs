// cli_desktop/dbus/ — a small D-Bus implementation, written for the
// Secret Service front end (and nothing else): signatures and values, the
// wire format, messages, the bus handshake and a threaded connection.
// Hand-written like kepr's X.509, SigV4 and FUSE code, so the binary stays
// free of an async runtime and a large dependency tree. File descriptor
// passing and the server side of the authentication handshake are not
// implemented; neither is needed to be a bus client.

pub mod addr;
pub mod auth;
pub mod conn;
pub mod marshal;
pub mod msg;
pub mod sig;
pub mod unmarshal;
pub mod value;

pub use conn::Conn;
pub use msg::Message;
pub use value::Value;

#[cfg(test)]
mod tests {
    use super::msg::{ERROR, METHOD_CALL, METHOD_RETURN, SIGNAL};
    use super::*;
    use std::collections::HashMap;

    fn vectors() -> HashMap<String, Vec<u8>> {
        let text = include_str!("testdata/jeepney.json");
        let raw: HashMap<String, String> = serde_json::from_str(text).unwrap();
        raw.into_iter()
            .map(|(k, v)| (k, hex::decode(v).unwrap()))
            .collect()
    }

    /// What jeepney, an independent implementation, wrote.
    #[test]
    fn messages_from_another_implementation_decode() {
        let v = vectors();
        let hello = Message::decode(&v["hello"]).unwrap();
        assert_eq!(hello.kind, METHOD_CALL);
        assert_eq!(hello.serial, 1);
        assert_eq!(hello.member.as_deref(), Some("Hello"));
        assert_eq!(hello.path.as_deref(), Some("/org/freedesktop/DBus"));
        assert_eq!(hello.destination.as_deref(), Some("org.freedesktop.DBus"));
        assert!(hello.body.is_empty());

        let open = Message::decode(&v["open_session"]).unwrap();
        assert_eq!(open.signature(), "sv");
        assert_eq!(open.body[0], Value::str("plain"));
        assert_eq!(open.body[1], Value::variant(Value::str("")));

        let search = Message::decode(&v["search_items"]).unwrap();
        let mut attrs = search.body[0].pairs_ss().unwrap();
        attrs.sort();
        assert_eq!(
            attrs,
            [
                ("user".to_string(), "alice".to_string()),
                (
                    "xdg:schema".to_string(),
                    "org.gnome.keyring.NetworkPassword".to_string()
                ),
            ]
        );

        let set = Message::decode(&v["set_secret"]).unwrap();
        assert_eq!(
            set.interface.as_deref(),
            Some("org.freedesktop.Secret.Item")
        );
        let s = set.body[0].as_struct().unwrap();
        assert_eq!(s[0], Value::path("/org/freedesktop/secrets/session/s1"));
        assert_eq!(s[1].as_bytes(), Some(&[1u8; 16][..]));
        assert_eq!(s[2].as_bytes(), Some(&b"hunter2"[..]));
        assert_eq!(s[3].as_str(), Some("text/plain; charset=utf8"));

        let props = Message::decode(&v["return_props"]).unwrap();
        assert_eq!(props.kind, METHOD_RETURN);
        assert_eq!((props.reply_serial, props.serial), (Some(3), 9));
        assert_eq!(props.destination.as_deref(), Some(":1.9"));
        let mut p: Vec<_> = props.body[0]
            .pairs_sv()
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, v.clone()))
            .collect();
        p.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(p[0], ("Created".to_string(), Value::U64(1_700_000_000)));
        assert_eq!(p[1], ("Label".to_string(), Value::str("login")));
        assert_eq!(p[2], ("Locked".to_string(), Value::Bool(false)));

        let paths = Message::decode(&v["return_paths"]).unwrap();
        assert_eq!(paths.body[0].strings().unwrap(), ["/a/b", "/c"]);
        assert_eq!(paths.body[1].strings().unwrap(), Vec::<String>::new());

        let sig = Message::decode(&v["signal_completed"]).unwrap();
        assert_eq!(sig.kind, SIGNAL);
        assert_eq!(sig.member.as_deref(), Some("Completed"));
        assert_eq!(sig.body[0], Value::Bool(false));
        assert_eq!(sig.body[1], Value::variant(Value::path("/")));
    }

    #[test]
    fn big_endian_messages_decode_the_same() {
        let v = vectors();
        assert_eq!(v["hello_be"][0], b'B');
        let hello = Message::decode(&v["hello_be"]).unwrap();
        assert_eq!(hello.member.as_deref(), Some("Hello"));
        assert_eq!(hello.serial, 1);
        let s = Message::decode(&v["search_be"]).unwrap();
        assert_eq!(s.serial, 5);
        assert_eq!(
            s.body[0].pairs_ss().unwrap(),
            [("a".to_string(), "b".to_string())]
        );
    }

    #[test]
    fn what_we_encode_decodes_to_the_same_message() {
        let secret = Value::Struct(vec![
            Value::path("/org/freedesktop/secrets/session/s1"),
            Value::Bytes(vec![9; 16]),
            Value::Bytes(b"s3cret".to_vec()),
            Value::str("text/plain"),
        ]);
        for (i, m) in [
            Message::call(
                "org.freedesktop.secrets",
                "/org/freedesktop/secrets",
                "org.freedesktop.Secret.Service",
                "SearchItems",
                vec![Value::dict_ss(&std::collections::BTreeMap::new())],
            ),
            Message::call(
                ":1.2",
                "/x",
                "a.b",
                "M",
                vec![Value::U32(1), secret.clone(), Value::variant(Value::U64(3))],
            ),
            Message::signal(
                "/s",
                "org.freedesktop.Secret.Prompt",
                "Completed",
                vec![Value::Bool(true), Value::variant(Value::paths(vec![]))],
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let bytes = m.encode(40 + i as u32).unwrap();
            assert!(bytes.len().is_multiple_of(8) || !m.body.is_empty());
            let back = Message::decode(&bytes).unwrap();
            assert_eq!(back.serial, 40 + i as u32);
            assert_eq!(Message { serial: 0, ..back }, Message { serial: 0, ..m });
        }
        // A reply goes back to whoever sent the call.
        let mut call = Message::call("x.y", "/p", "i.f", "M", vec![]);
        call.sender = Some(":1.9".into());
        call.serial = 7;
        let r = call.reply_to(vec![Value::str("ok")]);
        assert_eq!(
            (r.kind, r.reply_serial, r.destination.as_deref()),
            (METHOD_RETURN, Some(7), Some(":1.9"))
        );
        let e = call.error_to("org.freedesktop.Secret.Error.IsLocked", "locked");
        assert_eq!(
            (e.kind, e.error_name.as_deref()),
            (ERROR, Some("org.freedesktop.Secret.Error.IsLocked"))
        );
        let back = Message::decode(&e.encode(8).unwrap()).unwrap();
        assert_eq!(back.body[0], Value::str("locked"));
    }

    #[test]
    fn broken_messages_are_errors() {
        let v = vectors();
        let good = &v["search_items"];
        for cut in [0, 5, 15, 16, 40, good.len() - 1] {
            assert!(Message::decode(&good[..cut]).is_err(), "cut at {cut}");
        }
        let mut longer = good.clone();
        longer.push(0);
        assert!(Message::decode(&longer).is_err());
        let mut bad_version = good.clone();
        bad_version[3] = 2;
        assert!(Message::decode(&bad_version).is_err());
        let mut bad_type = good.clone();
        bad_type[1] = 9;
        assert!(Message::decode(&bad_type).is_err());
        let mut zero_serial = good.clone();
        zero_serial[8..12].copy_from_slice(&[0; 4]);
        assert!(Message::decode(&zero_serial).is_err());
        // A header claiming a gigabyte.
        let mut huge = good.clone();
        huge[4..8].copy_from_slice(&0x4000_0000u32.to_le_bytes());
        assert!(Message::decode(&huge).is_err());
        assert!(Message::total_len(&[b'x'; 16]).is_err());
    }

    /// Any process on the session bus can send us bytes: whatever they
    /// are, decoding ends in a value or an error, never a panic or a huge
    /// allocation. Truncations and random mutations of real messages.
    #[test]
    fn mangled_messages_never_panic() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut samples: Vec<Vec<u8>> = vectors().into_values().collect();
        let big = Message::call(
            "a.b",
            "/p",
            "a.b",
            "M",
            vec![
                Value::dict_sv(vec![
                    ("k".into(), Value::str("v")),
                    ("n".into(), Value::U32(7)),
                ]),
                Value::Struct(vec![
                    Value::path("/x"),
                    Value::Bytes(vec![9; 40]),
                    Value::str("t"),
                ]),
                Value::variant(Value::paths(vec!["/a".into(), "/b".into()])),
            ],
        );
        samples.push(big.encode(1).unwrap().to_vec());
        for good in &samples {
            for cut in 0..good.len() {
                let _ = Message::decode(&good[..cut]);
            }
            for _ in 0..1500 {
                let mut m = good.clone();
                for _ in 0..=(next() % 4) {
                    let i = (next() as usize) % m.len();
                    m[i] = next() as u8;
                }
                let _ = Message::decode(&m);
                if m.len() >= 16 {
                    let mut head = [0u8; 16];
                    head.copy_from_slice(&m[..16]);
                    if let Ok(total) = Message::total_len(&head) {
                        assert!(total <= super::msg::MAX_MESSAGE, "{total}");
                    }
                }
            }
        }
        // Pure noise, too.
        for _ in 0..3000 {
            let n = (next() % 200) as usize;
            let junk: Vec<u8> = (0..n).map(|_| next() as u8).collect();
            let _ = Message::decode(&junk);
        }
    }

    #[test]
    fn names_are_checked() {
        use super::msg::{valid_bus_name, valid_interface, valid_member};
        assert!(valid_interface("org.freedesktop.Secret.Service"));
        assert!(!valid_interface("nodots") && !valid_interface("a..b") && !valid_interface("a.1b"));
        assert!(valid_member("GetAll") && !valid_member("get all") && !valid_member(""));
        assert!(
            valid_bus_name(":1.42")
                && valid_bus_name("org.freedesktop.secrets")
                && valid_bus_name("a.b-c")
        );
        assert!(!valid_bus_name(":") && !valid_bus_name("single") && !valid_bus_name("a.b c"));
    }
}
