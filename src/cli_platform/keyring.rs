// cli_platform/keyring.rs — `kepr keyring add KEY --desc SUBTYPE:REST
// [--keyring @u|@s|@us|SERIAL] [--decode hex|base64]` (T10.05).
//
// Adds KEY's value to a kernel keyring as a `logon` key with add_key(2).
// Logon keys can be used by the kernel (fscrypt, dm-crypt, cifs, …) but
// never read back from userspace: KEYCTL_READ fails with EOPNOTSUPP. The
// value is fetched like `kepr get` (sealed / ssh / share keys refused by
// the daemon) and stays in zeroizing buffers until the syscall.

use kepr_core::protocol::Response;
use kepr_core::protocol_platform::PlatformResponse;
use zeroize::Zeroizing;

use super::args;
use crate::cli_exec::{CredFetcher, DaemonFetcher};

const USAGE: &str =
    "usage: kepr keyring add KEY --desc SUBTYPE:REST [--keyring @u|@s|@us|SERIAL] [--decode hex|base64]";

// Special keyring ids (linux/keyctl.h).
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
const KEY_SPEC_USER_KEYRING: i32 = -4;
const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;

/// The kernel's per-key payload cap for `user`/`logon` keys.
const MAX_PAYLOAD: usize = 32767;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decode {
    Raw,
    Hex,
    Base64,
}

#[derive(Debug)]
pub struct Opts {
    pub name: String,
    pub desc: String,
    /// As typed (`@u`), for messages.
    pub keyring_label: String,
    pub keyring: i32,
    pub decode: Decode,
}

pub fn parse(argv: &[String]) -> Result<Opts, String> {
    let a = args::parse(argv, &["--desc", "--keyring", "--decode"], &[])?;
    let [sub, name] = a.positional.as_slice() else {
        return Err(USAGE.into());
    };
    if sub != "add" {
        return Err(USAGE.into());
    }
    let desc = a.value("--desc").ok_or(USAGE)?.to_string();
    validate_desc(&desc)?;
    let keyring_label = a.value("--keyring").unwrap_or("@u").to_string();
    let keyring = parse_keyring(&keyring_label)?;
    let decode = match a.value("--decode") {
        None => Decode::Raw,
        Some("hex") => Decode::Hex,
        Some("base64") => Decode::Base64,
        Some(_) => return Err("--decode: use hex or base64".into()),
    };
    Ok(Opts {
        name: name.to_uppercase(),
        desc,
        keyring_label,
        keyring,
        decode,
    })
}

/// A logon key's description must be `SUBTYPE:REST` (the kernel refuses
/// one without a non-empty subtype). Printable ASCII without spaces, so
/// it reads unambiguously in /proc/keys.
pub fn validate_desc(desc: &str) -> Result<(), String> {
    let bad = || {
        "--desc: use SUBTYPE:REST, e.g. fscrypt:0123456789abcdef (printable, no spaces)".to_string()
    };
    if desc.is_empty() || desc.len() > 4095 || !desc.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad());
    }
    let (subtype, rest) = desc.split_once(':').ok_or_else(bad)?;
    let subtype_ok = !subtype.is_empty()
        && subtype
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !subtype_ok || rest.is_empty() {
        return Err(bad());
    }
    // fscrypt v1 (and its legacy ext4/f2fs prefixes) looks keys up by an
    // 8-byte descriptor written as 16 hex digits.
    if matches!(subtype, "fscrypt" | "ext4" | "f2fs")
        && (rest.len() != 16 || !rest.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(format!(
            "--desc: {subtype}: needs a 16-hex-digit key descriptor"
        ));
    }
    Ok(())
}

/// `@u` (user), `@s` (session), `@us` (user session) or a keyring serial.
/// Thread and process keyrings would vanish when kepr exits.
pub fn parse_keyring(s: &str) -> Result<i32, String> {
    match s {
        "@u" => Ok(KEY_SPEC_USER_KEYRING),
        "@s" => Ok(KEY_SPEC_SESSION_KEYRING),
        "@us" => Ok(KEY_SPEC_USER_SESSION_KEYRING),
        "@t" | "@p" => Err(format!(
            "--keyring {s}: that keyring goes away when kepr exits; use @u, @s or @us"
        )),
        _ => match s.parse::<i32>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err("--keyring: use @u, @s, @us or a keyring serial number".into()),
        },
    }
}

/// The bytes handed to the kernel.
pub fn payload(value: &str, decode: Decode) -> Result<Zeroizing<Vec<u8>>, String> {
    let bytes = match decode {
        Decode::Raw => Zeroizing::new(value.as_bytes().to_vec()),
        Decode::Hex => Zeroizing::new(
            hex::decode(value.trim()).map_err(|_| "value is not valid hex".to_string())?,
        ),
        Decode::Base64 => {
            use base64::Engine;
            Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(value.trim())
                    .map_err(|_| "value is not valid base64".to_string())?,
            )
        }
    };
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err(format!(
            "a logon key holds 1 to {MAX_PAYLOAD} bytes; this value has {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// add_key(2) with type `logon`. Returns the new key's serial or errno.
#[cfg(target_os = "linux")]
pub fn add_logon(desc: &str, payload: &[u8], keyring: i32) -> Result<i32, i32> {
    let desc = std::ffi::CString::new(desc).map_err(|_| libc::EINVAL)?;
    // SAFETY: both strings are NUL-terminated and live across the call;
    // the payload pointer/length pair describes a valid slice.
    let r = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            c"logon".as_ptr(),
            desc.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            keyring,
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(r as i32)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn add_logon(_desc: &str, _payload: &[u8], _keyring: i32) -> Result<i32, i32> {
    Err(38) // ENOSYS
}

fn errno_message(errno: i32) -> String {
    match errno {
        libc::EDQUOT => "the keyring's quota is full".into(),
        libc::ENOKEY => "no such keyring".into(),
        libc::EACCES | libc::EPERM => "not allowed to add keys to that keyring".into(),
        libc::ENOSYS => "kernel keyrings are not available here".into(),
        libc::EINVAL => "the kernel refused the description or value".into(),
        n => format!("add_key failed: {}", std::io::Error::from_raw_os_error(n)),
    }
}

pub fn run(opts: &Opts, fetcher: &dyn CredFetcher) -> Result<i32, String> {
    let value = fetcher.fetch(&opts.name)?;
    let bytes = payload(value.as_str(), opts.decode)?;
    drop(value);
    add_logon(&opts.desc, &bytes, opts.keyring).map_err(errno_message)
}

pub fn cmd_keyring(argv: &[String]) -> Response {
    let opts = match parse(argv) {
        Ok(o) => o,
        Err(e) => return Response::fail(e),
    };
    match run(&opts, &DaemonFetcher) {
        Ok(serial) => {
            if !crate::cli_ui::json_mode() {
                println!(
                    "added {} as logon key {} (serial {serial}) to {}",
                    opts.name, opts.desc, opts.keyring_label
                );
            }
            Response::Platform(PlatformResponse::KeyringAdded {
                name: opts.name,
                desc: opts.desc,
                keyring: opts.keyring_label,
                serial,
            })
        }
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn description_needs_the_subtype_prefix_form() {
        for ok in [
            "fscrypt:0123456789abcdef",
            "cifs:a:192.0.2.1",
            "cryptsetup:vol-1",
            "my_app:token",
        ] {
            assert!(validate_desc(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "nocolon",
            ":rest",
            "subtype:",
            "has space:x",
            "sub type:x",
            "fscrypt:short",
            "fscrypt:0123456789abcdeg",
            "ext4:00",
        ] {
            assert!(validate_desc(bad).is_err(), "{bad:?}");
        }
        assert!(validate_desc(&format!("x:{}", "a".repeat(5000))).is_err());
    }

    #[test]
    fn keyring_and_argument_parsing() {
        assert_eq!(parse_keyring("@u"), Ok(KEY_SPEC_USER_KEYRING));
        assert_eq!(parse_keyring("@s"), Ok(KEY_SPEC_SESSION_KEYRING));
        assert_eq!(parse_keyring("@us"), Ok(KEY_SPEC_USER_SESSION_KEYRING));
        assert_eq!(parse_keyring("123"), Ok(123));
        for bad in ["@t", "@p", "0", "-4", "u", ""] {
            assert!(parse_keyring(bad).is_err(), "{bad:?}");
        }
        let o = parse(&v(&["add", "vol_key", "--desc", "cryptsetup:v"])).unwrap();
        assert_eq!(
            (o.name.as_str(), o.keyring, o.decode),
            ("VOL_KEY", KEY_SPEC_USER_KEYRING, Decode::Raw)
        );
        let o = parse(&v(&[
            "add",
            "K",
            "--desc",
            "a:b",
            "--keyring",
            "@s",
            "--decode",
            "hex",
        ]))
        .unwrap();
        assert_eq!(
            (o.keyring, o.decode),
            (KEY_SPEC_SESSION_KEYRING, Decode::Hex)
        );
        assert!(parse(&v(&["add", "K"])).is_err(), "--desc is required");
        assert!(parse(&v(&["rm", "K", "--desc", "a:b"])).is_err());
        assert!(parse(&v(&["add", "K", "--desc", "a:b", "--decode", "rot13"])).is_err());
    }

    #[test]
    fn payload_decoding_and_size_limits() {
        assert_eq!(*payload("abc", Decode::Raw).unwrap(), b"abc");
        assert_eq!(*payload("00ff\n", Decode::Hex).unwrap(), [0u8, 255]);
        assert_eq!(*payload("AAE=", Decode::Base64).unwrap(), [0u8, 1]);
        assert!(payload("zz", Decode::Hex).is_err());
        assert!(payload("", Decode::Raw).is_err());
        assert!(payload(&"a".repeat(MAX_PAYLOAD + 1), Decode::Raw).is_err());
    }

    #[cfg(target_os = "linux")]
    fn keyctl(op: libc::c_long, a: libc::c_long, b: libc::c_long, c: libc::c_long) -> i64 {
        // SAFETY: plain keyctl(2) call with integer / buffer arguments.
        unsafe { libc::syscall(libc::SYS_keyctl, op, a, b, c) }
    }

    /// The kernel half: a logon key goes in, and userspace can't read it
    /// back. Uses the thread keyring of a scratch thread so nothing
    /// outlives the test; skips where keyrings are filtered (containers).
    #[cfg(target_os = "linux")]
    #[test]
    fn logon_key_is_added_and_cannot_be_read_back() {
        const KEY_SPEC_THREAD_KEYRING: i32 = -1;
        const KEYCTL_READ: libc::c_long = 11;
        const KEYCTL_INVALIDATE: libc::c_long = 21;
        std::thread::spawn(|| {
            let serial = match add_logon("kepr-test:t1005", b"s3cret", KEY_SPEC_THREAD_KEYRING) {
                Ok(s) => s,
                Err(e) if [libc::ENOSYS, libc::EPERM, libc::EACCES].contains(&e) => {
                    eprintln!("skipping: kernel keyrings unavailable (errno {e})");
                    return;
                }
                Err(e) => panic!("add_key failed: errno {e}"),
            };
            assert!(serial > 0);
            let mut buf = [0u8; 64];
            let r = keyctl(
                KEYCTL_READ,
                serial as libc::c_long,
                buf.as_mut_ptr() as libc::c_long,
                buf.len() as libc::c_long,
            );
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert_eq!(r, -1);
            assert_eq!(errno, Some(libc::EOPNOTSUPP));
            assert_eq!(buf, [0u8; 64]);
            keyctl(KEYCTL_INVALIDATE, serial as libc::c_long, 0, 0);
            // A description without the subtype is refused by the kernel too.
            assert_eq!(
                add_logon("nocolon", b"x", KEY_SPEC_THREAD_KEYRING),
                Err(libc::EINVAL)
            );
        })
        .join()
        .unwrap();
    }
}
