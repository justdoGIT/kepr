// cli_platform/mount.rs — what `kepr mount` serves (T10.01).
//
// A flat read-only directory: one file per `--file NAME=KEY1,KEY2`. Nothing
// is fetched until a process opens a file; that open is checked (`Gate`:
// the caller's uid, optionally its executable digest and a consent prompt),
// then the values are fetched from the daemon, rendered, kept for that file
// handle only (zeroized on release) and served with FOPEN_DIRECT_IO so no
// page cache holds them. A refused open gets EACCES.
//
// Rendering: `*.json` → a JSON object; one key in a file that is not `.env`
// → the bare value; otherwise dotenv lines (`KEY=value`, quoted as needed).

use std::collections::HashMap;

use kepr_core::generate::ZeroString;
use zeroize::Zeroizing;

use super::fuse::{self, Attr, InHeader};
use crate::cli_exec::CredFetcher;

pub struct Spec {
    pub file: String,
    pub keys: Vec<String>,
}

/// `.env=DB_URL,API_KEY` → Spec.
pub fn parse_spec(s: &str) -> Result<Spec, String> {
    let (file, keys) = s
        .split_once('=')
        .ok_or_else(|| format!("--file {s}: expected NAME=KEY1,KEY2"))?;
    if file.is_empty()
        || file == "."
        || file == ".."
        || file.len() > 255
        || file.contains(['/', '\0'])
    {
        return Err(format!("--file {s}: not a plain file name"));
    }
    let keys: Vec<String> = keys
        .split(',')
        .map(|k| k.trim().to_ascii_uppercase())
        .collect();
    let ok = |k: &String| {
        !k.is_empty()
            && k.len() <= 128
            && k.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    };
    if let Some(k) = keys.iter().find(|k| !ok(k)) {
        return Err(format!("--file {s}: not a credential name: {k:?}"));
    }
    Ok(Spec {
        file: file.to_string(),
        keys,
    })
}

fn dotenv_value(v: &str) -> String {
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"_-./:@+,%".contains(&b);
    if !v.is_empty() && v.bytes().all(plain) {
        return v.to_string();
    }
    if !v.contains(['\'', '\n', '\r']) {
        return format!("'{v}'");
    }
    let mut out = String::from("\"");
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The bytes of `file` for these (name, value) pairs.
pub fn render(file: &str, pairs: &[(String, ZeroString)]) -> Zeroizing<Vec<u8>> {
    let lower = file.to_ascii_lowercase();
    if lower.ends_with(".json") {
        let map: serde_json::Map<String, serde_json::Value> = pairs
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.as_str().to_string())))
            .collect();
        let mut s = Zeroizing::new(serde_json::to_string_pretty(&map).unwrap_or_default());
        s.push('\n');
        return Zeroizing::new(s.as_bytes().to_vec());
    }
    if let ([(_, v)], false) = (pairs, lower.ends_with(".env")) {
        return Zeroizing::new(v.as_str().as_bytes().to_vec());
    }
    let mut out = Zeroizing::new(Vec::new());
    for (k, v) in pairs {
        let line = Zeroizing::new(format!("{k}={}\n", dotenv_value(v.as_str())));
        out.extend_from_slice(line.as_bytes());
    }
    out
}

/// Who may open a file: the request's uid and pid (in the mount's pid
/// namespace; the caller is blocked in open(2) while this runs).
pub trait Gate {
    fn check(&self, uid: u32, pid: u32) -> Result<(), String>;
}

pub struct Fs<'a> {
    pub files: Vec<Spec>,
    pub owner: (u32, u32),
    pub gate: &'a dyn Gate,
    pub fetch: &'a dyn CredFetcher,
    pub started: u64,
    open: HashMap<u64, Zeroizing<Vec<u8>>>,
    next_fh: u64,
    /// Set by DESTROY.
    pub done: bool,
}

impl<'a> Fs<'a> {
    pub fn new(
        files: Vec<Spec>,
        gate: &'a dyn Gate,
        fetch: &'a dyn CredFetcher,
        owner: (u32, u32),
        started: u64,
    ) -> Self {
        Fs {
            files,
            owner,
            gate,
            fetch,
            started,
            open: HashMap::new(),
            next_fh: 1,
            done: false,
        }
    }

    fn attr(&self, ino: u64, size: u64) -> Option<Attr> {
        let (mode, nlink) = match ino {
            fuse::ROOT => (libc::S_IFDIR | 0o500, 2),
            n if self.spec(n).is_some() => (libc::S_IFREG | 0o400, 1),
            _ => return None,
        };
        Some(Attr {
            ino,
            size,
            mode,
            nlink,
            uid: self.owner.0,
            gid: self.owner.1,
            time: self.started,
        })
    }

    fn spec(&self, ino: u64) -> Option<&Spec> {
        ino.checked_sub(2).and_then(|i| self.files.get(i as usize))
    }

    /// Answer one request; `None` for requests that take no reply.
    pub fn handle(&mut self, req: &[u8]) -> Option<Vec<u8>> {
        let (h, body) = fuse::parse(req)?;
        let r = |res: Result<Vec<u8>, i32>| match res {
            Ok(b) => fuse::reply(h.unique, 0, &b),
            Err(e) => fuse::reply(h.unique, -e, &[]),
        };
        Some(r(match h.opcode {
            fuse::FORGET | fuse::BATCH_FORGET | fuse::INTERRUPT => return None,
            fuse::INIT => fuse::init(body),
            fuse::DESTROY => {
                self.done = true;
                Ok(Vec::new())
            }
            fuse::LOOKUP => self.lookup(&h, body),
            fuse::GETATTR => {
                let (flags, fh) = fuse::getattr_in(body);
                let size = match (flags & fuse::GETATTR_FH != 0, self.open.get(&fh)) {
                    (true, Some(c)) => c.len() as u64,
                    _ => 0,
                };
                self.attr(h.nodeid, size)
                    .map(|a| fuse::attr_out(&a))
                    .ok_or(libc::ENOENT)
            }
            fuse::OPEN => self.open_file(&h, body),
            fuse::READ => self.read(body),
            fuse::RELEASE => {
                fuse::release_fh(body).and_then(|fh| self.open.remove(&fh));
                Ok(Vec::new())
            }
            fuse::OPENDIR if h.nodeid == fuse::ROOT => Ok(fuse::open_out(0, 0)),
            fuse::OPENDIR => Err(libc::ENOTDIR),
            fuse::READDIR => self.readdir(&h, body),
            fuse::RELEASEDIR | fuse::FLUSH | fuse::ACCESS => Ok(Vec::new()),
            fuse::STATFS => Ok(fuse::statfs_out(self.files.len() as u64)),
            _ => Err(libc::ENOSYS),
        }))
    }

    fn lookup(&self, h: &InHeader, body: &[u8]) -> Result<Vec<u8>, i32> {
        if h.nodeid != fuse::ROOT {
            return Err(libc::ENOENT);
        }
        let name = fuse::lookup_name(body);
        let i = self
            .files
            .iter()
            .position(|s| s.file.as_bytes() == name)
            .ok_or(libc::ENOENT)?;
        let a = self.attr(i as u64 + 2, 0).ok_or(libc::ENOENT)?;
        Ok(fuse::entry_out(&a))
    }

    fn open_file(&mut self, h: &InHeader, body: &[u8]) -> Result<Vec<u8>, i32> {
        let spec = self.spec(h.nodeid).ok_or(if h.nodeid == fuse::ROOT {
            libc::EISDIR
        } else {
            libc::ENOENT
        })?;
        let file = spec.file.clone();
        let deny = |why: String| {
            eprintln!(
                "kepr mount: refused {file} to pid {} (uid {}): {why}",
                h.pid, h.uid
            );
            libc::EACCES
        };
        if fuse::open_flags(body).unwrap_or(0) & libc::O_ACCMODE as u32 != libc::O_RDONLY as u32 {
            return Err(deny("read-only".into()));
        }
        if h.uid != self.owner.0 {
            return Err(deny("not the mount owner".into()));
        }
        self.gate.check(h.uid, h.pid).map_err(deny)?;
        let mut pairs = Vec::with_capacity(spec.keys.len());
        for k in &spec.keys {
            pairs.push((
                k.clone(),
                self.fetch.fetch(k).map_err(|e| deny(format!("{k}: {e}")))?,
            ));
        }
        let content = render(&file, &pairs);
        let fh = self.next_fh;
        self.next_fh += 1;
        self.open.insert(fh, content);
        eprintln!("kepr mount: {file} opened by pid {}", h.pid);
        Ok(fuse::open_out(fh, fuse::FOPEN_DIRECT_IO))
    }

    fn read(&self, body: &[u8]) -> Result<Vec<u8>, i32> {
        let (fh, off, size) = fuse::read_in(body).ok_or(libc::EINVAL)?;
        let c = self.open.get(&fh).ok_or(libc::EBADF)?;
        let start = (off as usize).min(c.len());
        let end = start.saturating_add(size as usize).min(c.len());
        Ok(c[start..end].to_vec())
    }

    fn readdir(&self, h: &InHeader, body: &[u8]) -> Result<Vec<u8>, i32> {
        if h.nodeid != fuse::ROOT {
            return Err(libc::ENOTDIR);
        }
        let (_, off, size) = fuse::read_in(body).ok_or(libc::EINVAL)?;
        let names = [(fuse::ROOT, 4u32, "."), (fuse::ROOT, 4, "..")]
            .into_iter()
            .chain(
                self.files
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (i as u64 + 2, 8, s.file.as_str())),
            );
        let mut out = Vec::new();
        for (i, (ino, dtype, name)) in names.enumerate().skip(off as usize) {
            if !fuse::dirent(&mut out, size as usize, ino, i as u64 + 1, dtype, name) {
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::super::fuse::tests::request;
    use super::*;
    use std::cell::RefCell;

    struct Values;
    impl CredFetcher for Values {
        fn fetch(&self, name: &str) -> Result<ZeroString, String> {
            match name {
                "DB_URL" => Ok(ZeroString::from_string("postgres://u:p@h/db".into())),
                "API_KEY" => Ok(ZeroString::from_string("it's \"x\"\nline2".into())),
                _ => Err("credential unavailable".into()),
            }
        }
    }

    /// Allows pid 4242 only; remembers who asked.
    struct OnlyPid(RefCell<Vec<u32>>);
    impl Gate for OnlyPid {
        fn check(&self, _uid: u32, pid: u32) -> Result<(), String> {
            self.0.borrow_mut().push(pid);
            (pid == 4242)
                .then_some(())
                .ok_or_else(|| "not allowed".into())
        }
    }

    fn fs<'a>(gate: &'a OnlyPid) -> Fs<'a> {
        let files = [
            "app.env=DB_URL,API_KEY",
            "config.json=DB_URL,API_KEY",
            "token=DB_URL",
            "bad=NOPE",
        ]
        .iter()
        .map(|s| parse_spec(s).unwrap())
        .collect();
        Fs::new(files, gate, &Values, (1000, 1000), 1_700_000_000)
    }

    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    /// (error, body) of a reply.
    fn split(r: &[u8]) -> (i32, &[u8]) {
        assert_eq!(u32_at(r, 0) as usize, r.len());
        (u32_at(r, 4) as i32, &r[16..])
    }

    fn read_req(fh: u64, off: u64, size: u32) -> Vec<u8> {
        let mut b = fh.to_le_bytes().to_vec();
        b.extend(off.to_le_bytes());
        b.extend(size.to_le_bytes());
        b.extend([0u8; 20]);
        b
    }

    fn open(fs: &mut Fs, ino: u64, pid: u32, flags: u32) -> Result<u64, i32> {
        let r = fs
            .handle(&request(
                fuse::OPEN,
                9,
                ino,
                1000,
                pid,
                &[flags.to_le_bytes(), [0; 4]].concat(),
            ))
            .unwrap();
        match split(&r) {
            (0, b) => {
                assert_eq!(u32_at(b, 8), fuse::FOPEN_DIRECT_IO);
                Ok(u64::from_le_bytes(b[..8].try_into().unwrap()))
            }
            (e, _) => Err(-e),
        }
    }

    fn read_all(fs: &mut Fs, fh: u64) -> String {
        let r = fs
            .handle(&request(
                fuse::READ,
                10,
                2,
                1000,
                4242,
                &read_req(fh, 0, 4096),
            ))
            .unwrap();
        String::from_utf8(split(&r).1.to_vec()).unwrap()
    }

    #[test]
    fn lookup_getattr_readdir() {
        let g = OnlyPid(RefCell::new(Vec::new()));
        let mut fs = fs(&g);
        let r = fs
            .handle(&request(
                fuse::LOOKUP,
                1,
                fuse::ROOT,
                1000,
                1,
                b"config.json\0",
            ))
            .unwrap();
        let (err, body) = split(&r);
        assert_eq!(err, 0);
        assert_eq!(u64::from_le_bytes(body[..8].try_into().unwrap()), 3);
        assert_eq!(u32_at(body, 40 + 60), libc::S_IFREG | 0o400);
        let r = fs
            .handle(&request(fuse::LOOKUP, 2, fuse::ROOT, 1000, 1, b"nope\0"))
            .unwrap();
        assert_eq!(split(&r).0, -libc::ENOENT);
        let r = fs
            .handle(&request(fuse::GETATTR, 3, fuse::ROOT, 1000, 1, &[0; 16]))
            .unwrap();
        let (err, body) = split(&r);
        assert_eq!((err, u32_at(body, 16 + 60)), (0, libc::S_IFDIR | 0o500));
        assert_eq!(u32_at(body, 16 + 68), 1000);
        let r = fs
            .handle(&request(
                fuse::READDIR,
                4,
                fuse::ROOT,
                1000,
                1,
                &read_req(0, 0, 4096),
            ))
            .unwrap();
        let listing = String::from_utf8_lossy(split(&r).1).to_string();
        for n in ["app.env", "config.json", "token", "bad"] {
            assert!(listing.contains(n), "{n}");
        }
        assert!(g.0.borrow().is_empty(), "nothing opened, nothing checked");
        assert!(fs
            .handle(&request(fuse::FORGET, 5, 2, 1000, 1, &[0; 8]))
            .is_none());
        let r = fs.handle(&request(99, 6, 2, 1000, 1, &[])).unwrap();
        assert_eq!(split(&r).0, -libc::ENOSYS);
    }

    #[test]
    fn open_renders_and_release_forgets() {
        let g = OnlyPid(RefCell::new(Vec::new()));
        let mut fs = fs(&g);
        let fh = open(&mut fs, 2, 4242, libc::O_RDONLY as u32).unwrap();
        assert_eq!(
            read_all(&mut fs, fh),
            "DB_URL=postgres://u:p@h/db\nAPI_KEY=\"it's \\\"x\\\"\\nline2\"\n"
        );
        // GETATTR on the open handle reports the real size.
        let mut ga = fuse::GETATTR_FH.to_le_bytes().to_vec();
        ga.extend([0; 4]);
        ga.extend(fh.to_le_bytes());
        let r = fs
            .handle(&request(fuse::GETATTR, 11, 2, 1000, 4242, &ga))
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(split(&r).1[16 + 8..16 + 16].try_into().unwrap()),
            55
        );
        // Reads past the end are empty; partial reads are slices.
        let r = fs
            .handle(&request(fuse::READ, 12, 2, 1000, 4242, &read_req(fh, 7, 8)))
            .unwrap();
        assert_eq!(split(&r).1, b"postgres");
        let r = fs
            .handle(&request(
                fuse::READ,
                13,
                2,
                1000,
                4242,
                &read_req(fh, 1000, 8),
            ))
            .unwrap();
        assert_eq!(split(&r), (0, &b""[..]));
        let json = open(&mut fs, 3, 4242, 0).unwrap();
        let v: serde_json::Value = serde_json::from_str(&read_all(&mut fs, json)).unwrap();
        assert_eq!(v["DB_URL"], "postgres://u:p@h/db");
        assert_eq!(v["API_KEY"], "it's \"x\"\nline2");
        let raw = open(&mut fs, 4, 4242, 0).unwrap();
        assert_eq!(read_all(&mut fs, raw), "postgres://u:p@h/db");
        let r = fs
            .handle(&request(
                fuse::RELEASE,
                14,
                2,
                1000,
                4242,
                &[fh.to_le_bytes(), [0; 8], [0; 8]].concat(),
            ))
            .unwrap();
        assert_eq!(split(&r).0, 0);
        let r = fs
            .handle(&request(fuse::READ, 15, 2, 1000, 4242, &read_req(fh, 0, 8)))
            .unwrap();
        assert_eq!(split(&r).0, -libc::EBADF);
    }

    #[test]
    fn denied_opens_return_eacces() {
        let g = OnlyPid(RefCell::new(Vec::new()));
        let mut fs = fs(&g);
        assert_eq!(open(&mut fs, 2, 7, 0), Err(libc::EACCES), "gate refuses");
        assert_eq!(
            open(&mut fs, 2, 4242, libc::O_WRONLY as u32),
            Err(libc::EACCES)
        );
        assert_eq!(
            open(&mut fs, 2, 4242, libc::O_RDWR as u32),
            Err(libc::EACCES)
        );
        assert_eq!(
            open(&mut fs, 5, 4242, 0),
            Err(libc::EACCES),
            "value unavailable"
        );
        // Another uid (only possible with allow_other) never reaches the gate.
        let r = fs
            .handle(&request(fuse::OPEN, 16, 2, 1001, 4242, &[0; 8]))
            .unwrap();
        assert_eq!(split(&r).0, -libc::EACCES);
        assert_eq!(
            *g.0.borrow(),
            [7, 4242],
            "checked once per allowed-uid read-only open"
        );
        assert_eq!(open(&mut fs, fuse::ROOT, 4242, 0), Err(libc::EISDIR));
    }

    #[test]
    fn specs_and_rendering() {
        let s = parse_spec(".env=db_url, api_key").unwrap();
        assert_eq!(
            (s.file.as_str(), s.keys.as_slice()),
            (".env", &["DB_URL".to_string(), "API_KEY".into()][..])
        );
        for bad in ["x", "=A", "a/b=A", "..=A", "f=", "f=A,", "f=A-B"] {
            assert!(parse_spec(bad).is_err(), "{bad}");
        }
        let v = |s: &str| ZeroString::from_string(s.into());
        let pairs = vec![
            ("A".to_string(), v("plain-1.2")),
            ("B".to_string(), v("has space $HOME")),
        ];
        assert_eq!(
            &render(".env", &pairs)[..],
            b"A=plain-1.2\nB='has space $HOME'\n"
        );
        assert_eq!(&render("one.env", &pairs[..1])[..], b"A=plain-1.2\n");
        assert_eq!(&render("token", &pairs[1..])[..], b"has space $HOME");
        assert_eq!(
            &render("x.JSON", &pairs[..1])[..],
            b"{\n  \"A\": \"plain-1.2\"\n}\n"
        );
    }
}
