//! Immutable indexes preserve credential identity across destination aliases.
use super::{Route, State};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default)]
pub(super) struct Index {
    hosts: HashMap<String, Arc<HashMap<String, String>>>,
    slots: HashMap<u16, String>,
}
impl Index {
    pub fn new(routes: &HashMap<String, Route>) -> Self {
        let mut hosts: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut slots = HashMap::new();
        for (name, route) in routes {
            slots.insert(route.slot, route.cred.clone());
            if let Some((host, _)) = kepr_core::http_route::parse(name) {
                hosts
                    .entry(host.into())
                    .or_default()
                    .insert(route.cred.clone(), name.clone());
            }
        }
        Self {
            hosts: hosts.into_iter().map(|(h, r)| (h, Arc::new(r))).collect(),
            slots,
        }
    }
    pub fn host(&self, host: &str) -> Option<Arc<HashMap<String, String>>> {
        self.hosts.get(host).cloned()
    }
    pub fn select<'a>(
        &self,
        state: &State,
        routes: &'a HashMap<String, String>,
        phs: &[String],
    ) -> Option<(&'a str, u16)> {
        let first = crate::placeholder::parse(phs.first()?)?;
        if !phs.iter().all(|p| state.valid_placeholder(p, first.slot)) {
            return None;
        }
        let cred = self.slots.get(&first.slot)?;
        Some((routes.get(cred)?.as_str(), first.slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Cache, Resolve, DEFAULT_TTL};
    use kepr_core::{binding::Inject, generate::ZeroString, secmem::SplitKey};
    struct NoVault;
    impl Resolve for NoVault {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            panic!("authorization must not resolve secrets");
        }
    }
    #[test]
    fn selection_requires_one_authenticated_credential_bound_to_destination() {
        let key = [7; 32];
        let sid = "0123456789abcdef";
        let routes = [
            ("alpha.example", "ALPHA"),
            ("beta.example", "BETA"),
            ("alias.example", "ALPHA"),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, (h, c))| {
            (
                kepr_core::http_route::key(h, c).unwrap(),
                Route {
                    cred: c.into(),
                    slot: i as u16,
                },
            )
        })
        .collect();
        let state = State::new(
            sid.into(),
            SplitKey::new(&key).unwrap(),
            routes,
            Arc::new(Cache::new(Box::new(NoVault), DEFAULT_TTL)),
        );
        let a = crate::placeholder::make(&key, sid, 0);
        let b = crate::placeholder::make(&key, sid, 1);
        let beta = state.configured_routes("beta.example").unwrap();
        for phs in [
            vec![],
            vec![a.clone()],
            vec![a.clone(), b.clone()],
            vec!["invalid".into()],
        ] {
            assert!(state.route_index.select(&state, &beta, &phs).is_none());
        }
        let alias = state.configured_routes("alias.example").unwrap();
        assert_eq!(state.route_index.select(&state, &alias, &[a]).unwrap().1, 0);
        assert_eq!(state.route_index.select(&state, &beta, &[b]).unwrap().1, 1);
    }
}
