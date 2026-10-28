// cli_desktop/ss/prompt.rs — Prompt objects. The only prompt this server
// has is "unlock kepr": a client that finds the store locked asks to unlock
// the objects, gets a prompt back, calls `Prompt` on it and waits for the
// `Completed` signal.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const MAX_PER_OWNER: usize = 16;

pub struct PromptState {
    pub owner: String,
    /// Object paths the client asked to unlock.
    pub objects: Vec<String>,
    started: bool,
    pub cancel: Arc<AtomicBool>,
}

#[derive(Default)]
pub struct Prompts(Mutex<HashMap<String, PromptState>>);

fn fresh_id() -> String {
    let mut b = [0u8; 6];
    let _ = getrandom::fill(&mut b);
    format!("p{}", hex::encode(b))
}

impl Prompts {
    fn m(&self) -> std::sync::MutexGuard<'_, HashMap<String, PromptState>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn create(&self, owner: &str, objects: Vec<String>) -> Option<String> {
        let mut m = self.m();
        if m.values().filter(|p| p.owner == owner).count() >= MAX_PER_OWNER {
            return None;
        }
        let id = fresh_id();
        m.insert(
            id.clone(),
            PromptState {
                owner: owner.into(),
                objects,
                started: false,
                cancel: Arc::new(AtomicBool::new(false)),
            },
        );
        Some(id)
    }

    /// Start the prompt `id` for `owner`: its objects and cancel flag, or
    /// None if it is not theirs or already running.
    pub fn start(&self, id: &str, owner: &str) -> Option<(Vec<String>, Arc<AtomicBool>)> {
        let mut m = self.m();
        let p = m.get_mut(id).filter(|p| p.owner == owner && !p.started)?;
        p.started = true;
        Some((p.objects.clone(), Arc::clone(&p.cancel)))
    }

    pub fn exists(&self, id: &str, owner: &str) -> bool {
        self.m().get(id).is_some_and(|p| p.owner == owner)
    }

    /// Dismiss: cancel a running dialog. True if the prompt is the owner's.
    pub fn dismiss(&self, id: &str, owner: &str) -> bool {
        match self.m().get(id).filter(|p| p.owner == owner) {
            Some(p) => {
                p.cancel.store(true, Ordering::SeqCst);
                true
            }
            None => false,
        }
    }

    pub fn finish(&self, id: &str) {
        self.m().remove(id);
    }

    pub fn drop_owner(&self, owner: &str) {
        let mut m = self.m();
        m.retain(|_, p| {
            let keep = p.owner != owner;
            if !keep {
                p.cancel.store(true, Ordering::SeqCst);
            }
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prompt_runs_once_for_its_owner() {
        let p = Prompts::default();
        let id = p.create(":1.1", vec!["/a".into()]).unwrap();
        assert!(p.exists(&id, ":1.1") && !p.exists(&id, ":1.2"));
        assert!(p.start(&id, ":1.2").is_none(), "someone else's");
        let (objects, cancel) = p.start(&id, ":1.1").unwrap();
        assert_eq!(objects, ["/a"]);
        assert!(p.start(&id, ":1.1").is_none(), "already running");
        assert!(!cancel.load(Ordering::SeqCst));
        assert!(!p.dismiss(&id, ":1.2"));
        assert!(p.dismiss(&id, ":1.1"));
        assert!(cancel.load(Ordering::SeqCst));
        p.finish(&id);
        assert!(!p.exists(&id, ":1.1"));
    }

    #[test]
    fn a_vanished_client_cancels_its_prompts_and_floods_are_bounded() {
        let p = Prompts::default();
        let ids: Vec<_> = (0..MAX_PER_OWNER)
            .map(|_| p.create(":1.1", vec![]).unwrap())
            .collect();
        assert!(p.create(":1.1", vec![]).is_none());
        let (_, cancel) = p.start(&ids[0], ":1.1").unwrap();
        p.drop_owner(":1.1");
        assert!(cancel.load(Ordering::SeqCst));
        assert!(!p.exists(&ids[1], ":1.1"));
        assert!(p.create(":1.1", vec![]).is_some());
    }
}
