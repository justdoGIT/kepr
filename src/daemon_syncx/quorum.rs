// daemon_syncx/quorum.rs — T7.12 M-of-N approvals: the requirement, the
// approval requests and the windows they open.
//
// A credential with `.meta approvals = N` (2-9) is not read (`get` and
// every path that checks like `get`: copy, exec, share, export, sync,
// folders) nor resolved by an agent gate until N distinct approvers have
// approved a request for it; that opens a use window (1 h by default, at
// most 24 h). Approvers: the owner on this machine (polkit, counted once)
// and enrolled devices (quorum_device.rs), each once. A request expires
// after 15 minutes. Lowering N or turning it off is a request too, needing
// the current N. `set` keeps N (carry_over).
//
// On a credential that is just-in-time (T7.10 `jit`), an approved `Use`
// opens a T7.10 grant instead: a persisted window for any harness,
// marked `approved`, which is the only kind that satisfies this
// requirement (`daemon_aws::grant::open_approved`). Everywhere else the
// window lives in memory only, so a restarted daemon has none
// (fail-closed); the expiry sweeper closes those and bumps the gate
// generation. A gate that resolved the value inside a window drops it
// when the window ends (daemon_gate_deadline.rs). Deleting the
// credential drops its windows and requests (`forget`).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::expiry::{self, CredMeta};
use crate::store::cred_path;

pub const REQUEST_TTL: u64 = 15 * 60;
pub const MAX_WINDOW: u64 = 24 * 3600;
pub const MAX_APPROVALS: u8 = 9;
const MAX_PENDING: usize = 32;
/// The approver id of the owner's own (polkit) approval.
pub const OWNER: &str = "owner";

/// How an approver is named in messages (a device's id is its key).
pub fn shown(approver: &str) -> &'static str {
    if approver == OWNER {
        "the owner"
    } else {
        "that device"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Open a use window of this many seconds.
    Use(u64),
    /// Set the requirement to this (0: off).
    Relax(u8),
}

impl Action {
    pub fn text(&self) -> String {
        match *self {
            Action::Use(s) if s % 3600 == 0 => format!("use for {}h", s / 3600),
            Action::Use(s) if s % 60 == 0 => format!("use for {}m", s / 60),
            Action::Use(s) => format!("use for {s}s"),
            Action::Relax(0) => "turn approvals off".into(),
            Action::Relax(n) => format!("lower approvals to {n}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pending {
    pub id: String,
    pub uid: u32,
    pub name: String,
    pub action: Action,
    pub expires_at: u64,
    pub approvers: Vec<String>,
}

#[derive(Default)]
struct Reg {
    pending: Vec<Pending>,
    windows: HashMap<(u32, String), u64>,
}

static REG: Mutex<Option<Reg>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut Reg) -> T) -> T {
    let mut g = REG.lock().unwrap_or_else(|p| p.into_inner());
    f(g.get_or_insert_with(Reg::default))
}

/// The approvals `name` needs now (0: none).
pub fn need(uid: u32, name: &str) -> u8 {
    expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name)))
        .and_then(Result::ok)
        .and_then(|m| m.approvals)
        .unwrap_or(0)
}

/// Until when `name`'s approved window is open, if it is. On a
/// just-in-time credential (T7.10) that window is a grant in the meta.
pub fn window(uid: u32, name: &str, now: u64) -> Option<u64> {
    let in_memory = with(|r| r.windows.get(&(uid, name.to_string())).copied());
    let granted = || {
        let m = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name)))?.ok()?;
        crate::daemon_aws::grant::approved_until(&m)
    };
    in_memory.or_else(granted).filter(|u| *u > now)
}

/// The `get` / gate-resolve check: refused while approvals are required
/// and no approved window is open.
pub fn gate(uid: u32, name: &str, meta: &CredMeta, now: u64) -> Result<(), String> {
    // T7.10: on a just-in-time credential the approved grant is the
    // window; the owner's own `kepr grant` is not approved, so it
    // doesn't open this gate.
    // T7.10: on a just-in-time credential the window is an approved
    // grant (`window` reads it); the owner's own `kepr grant` is not
    // approved, so it doesn't open this gate.
    match meta.approvals {
        Some(n) if n >= 2 && window(uid, name, now).is_none() => {
            Err(format!("needs {n} approvals (kepr quorum request {name})"))
        }
        _ => Ok(()),
    }
}

/// `set` replaces the meta: keep the requirement.
pub fn carry_over(uid: u32, upper: &str, meta: &mut CredMeta) {
    if let Some(Ok(old)) = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) {
        meta.approvals = old.approvals;
    }
}

/// The sweeper: close windows and drop expired requests. A closed window
/// bumps the gate generation so gates drop what they cached.
pub fn sweep(now: u64) {
    let closed = with(|r| {
        let before = r.windows.len();
        r.windows.retain(|_, until| *until > now);
        r.pending.retain(|p| p.expires_at > now);
        r.windows.len() < before
    });
    if closed {
        crate::daemon_gate::bump_generation();
    }
}

/// `name` was deleted or moved away (its history is being purged): its
/// windows and open requests were approved for that value, never for
/// whatever is made under the name next.
pub fn forget(uid: u32, name: &str) {
    with(|r| {
        r.windows.remove(&(uid, name.to_string()));
        r.pending.retain(|p| p.uid != uid || p.name != name);
    });
}

/// A new request; its id.
pub fn open(uid: u32, name: &str, action: Action, now: u64) -> Result<Pending, String> {
    let mut id = [0u8; 4];
    getrandom::fill(&mut id).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let p = Pending {
        id: hex::encode(id),
        uid,
        name: name.to_string(),
        action,
        expires_at: now + REQUEST_TTL,
        approvers: Vec::new(),
    };
    with(|r| {
        r.pending.retain(|q| q.expires_at > now);
        if r.pending.iter().filter(|q| q.uid == uid).count() >= MAX_PENDING {
            return Err(format!("at most {MAX_PENDING} open approval requests"));
        }
        r.pending.push(p.clone());
        Ok(p)
    })
}

/// A live request of `uid`, or why not (an expired one is dropped).
pub fn find(uid: u32, id: &str, now: u64) -> Result<Pending, String> {
    with(|r| {
        let at = r
            .pending
            .iter()
            .position(|p| p.uid == uid && p.id == id)
            .ok_or("no such approval request (kepr quorum ls)")?;
        if r.pending[at].expires_at <= now {
            let p = r.pending.remove(at);
            return Err(format!(
                "approval request {id} expired; ask again (kepr quorum request {})",
                p.name
            ));
        }
        Ok(r.pending[at].clone())
    })
}

/// Count `approver` for request `id`. Returns the request after it;
/// when it has `need` approvals it is removed and its window (for a
/// `Use`) is open. The caller applies a `Relax`.
pub fn approve(
    uid: u32,
    id: &str,
    approver: &str,
    need: u8,
    now: u64,
) -> Result<(Pending, bool), String> {
    find(uid, id, now)?;
    let (p, done) = with(|r| {
        let at = r
            .pending
            .iter()
            .position(|p| p.uid == uid && p.id == id)
            .ok_or("no such approval request (kepr quorum ls)")?;
        let p = &mut r.pending[at];
        if p.approvers.iter().any(|a| a == approver) {
            return Err(format!("{} already approved request {id}", shown(approver)));
        }
        p.approvers.push(approver.to_string());
        if p.approvers.len() < usize::from(need.max(1)) {
            return Ok((p.clone(), false));
        }
        let p = r.pending.remove(at);
        Ok((p, true))
    })?;
    // Outside the registry lock: writing a T7.10 grant takes the
    // credential's lock, which other paths hold while reading here.
    if let (true, Action::Use(secs)) = (done, p.action) {
        let jit = crate::daemon_aws::grant::open_approved(uid, &p.name, secs, now)?;
        if !jit {
            with(|r| {
                let until = r.windows.entry((uid, p.name.clone())).or_insert(0);
                *until = (*until).max(now + secs);
            });
        }
    }
    Ok((p, done))
}

/// Open requests and windows of `uid`.
pub fn snapshot(uid: u32, now: u64) -> (Vec<Pending>, Vec<(String, u64)>) {
    with(|r| {
        let pending = r
            .pending
            .iter()
            .filter(|p| p.uid == uid && p.expires_at > now)
            .cloned()
            .collect();
        let windows = r
            .windows
            .iter()
            .filter(|((u, _), until)| *u == uid && **until > now)
            .map(|((_, n), until)| (n.clone(), *until))
            .collect();
        (pending, windows)
    })
}
