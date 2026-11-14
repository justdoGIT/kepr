use super::{FdResolver, Resolve};
use kepr_core::binding::Inject;
use kepr_core::gate_journal::{DecisionRecord, JournalEntry, ResultRecord};
use kepr_core::gate_protocol::{GateRequest, GateResponse};
use kepr_core::gate_record::GateRecord;
use kepr_core::generate::ZeroString;

impl Resolve for FdResolver {
    fn resolve(&self, name: &str, host: &str, port: u16) -> Result<(ZeroString, Inject), String> {
        let req = |id| GateRequest::Resolve {
            id,
            name: name.to_string(),
            host: host.to_string(),
            port,
        };
        match self.call(req)? {
            GateResponse::ResolveOk { value, inject, .. } => Ok((value, inject)),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn generation(&self) -> Result<u64, String> {
        match self.call(|id| GateRequest::Generation { id })? {
            GateResponse::Generation { generation, .. } => Ok(generation),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn record(&self, record: GateRecord) -> Result<(), String> {
        match self.call(|id| GateRequest::Record { id, record })? {
            GateResponse::Recorded { .. } => Ok(()),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn journal(&self, entries: Vec<JournalEntry>) -> Result<(), String> {
        match self.call(|id| GateRequest::Journal { id, entries })? {
            GateResponse::Recorded { .. } => Ok(()),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn decision(&self, record: DecisionRecord) -> Result<(), String> {
        self.acknowledged(|id| GateRequest::Decision { id, record })
    }

    fn result(&self, record: ResultRecord) -> Result<(), String> {
        self.acknowledged(|id| GateRequest::Result { id, record })
    }

    fn day_usage(&self, name: &str, requests: u64, tokens: u64) -> Result<(u64, u64), String> {
        let req = |id| GateRequest::DayUsage {
            id,
            name: name.to_string(),
            requests,
            tokens,
        };
        match self.call(req)? {
            GateResponse::UsageToday {
                requests, tokens, ..
            } => Ok((requests, tokens)),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn rotate_commit(&self, name: &str, value: &ZeroString) -> Result<(), String> {
        let req = |id| GateRequest::RotateCommit {
            id,
            name: name.to_string(),
            value: ZeroString::from(value.as_str()),
        };
        match self.call(req)? {
            GateResponse::Rotated { .. } => Ok(()),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn canary(&self, fingerprints: Vec<String>) -> Result<bool, String> {
        match self.call(|id| GateRequest::Canary { id, fingerprints })? {
            GateResponse::CanaryChecked { tripped, .. } => Ok(tripped),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }
}
