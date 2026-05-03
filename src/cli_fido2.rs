// cli_fido2.rs — FIDO2-register, FIDO2-list, and the `kepr get`
// assertion ceremony (Phase 2 η).

use crate::cli_args::Args;
use crate::cli_cmds::dispatch;
use crate::cli_ui::{bold, dim, err, info, ok};
use kepr_core::protocol::{Fido2Assertion, Request, Response};

pub fn cmd_fido2_register(a: &Args) -> Response {
    let Some(label) = a.name.clone() else {
        return Response::fail("fido2-register requires LABEL CRED_ID COSE_KEY");
    };
    let Some(cred_id) = a.fido2_credential_id.clone() else {
        return Response::fail("fido2-register requires CREDENTIAL_ID (hex)");
    };
    let Some(cose_key) = a.fido2_public_key_cose.clone() else {
        return Response::fail("fido2-register requires PUBLIC_KEY_COSE (hex)");
    };
    let resp = dispatch(
        a,
        &Request::Fido2Register {
            label,
            credential_id: cred_id,
            public_key_cose: cose_key,
        },
    );
    if !a.json {
        if let Response::Fido2RegisterOk { credential_id } = &resp {
            ok(&format!("FIDO2 key registered: {credential_id}"));
        } else if let Response::Err { error } = &resp {
            err(error);
        }
    }
    resp
}

pub fn cmd_fido2_list(a: &Args) -> Response {
    let resp = dispatch(a, &Request::Fido2List);
    if a.json {
        return resp;
    }
    match &resp {
        Response::Fido2ListOk { credentials } => {
            if credentials.is_empty() {
                info("No FIDO2 keys registered.");
                return resp;
            }
            println!();
            bold(&format!("  {} FIDO2 key(s):\n", credentials.len()));
            for c in credentials {
                print!("  {:24} ", c.label);
                dim(&c.credential_id);
            }
            println!();
        }
        Response::Err { error } => err(error),
        _ => err("unexpected response"),
    }
    resp
}

/// Run the FIDO2 assertion ceremony via `$KEPR_FIDO2_HELPER`.
/// Protocol: challenge + credential_ids on stdin as JSON,
/// assertion on stdout as JSON. Returns assertion on success.
pub fn run_fido2_ceremony(
    challenge: &str,
    credential_ids: &[String],
) -> Result<Fido2Assertion, String> {
    use std::process::Command;
    let helper =
        std::env::var("KEPR_FIDO2_HELPER").map_err(|_| "KEPR_FIDO2_HELPER not set".to_string())?;
    let input = serde_json::json!({
        "challenge": challenge,
        "credential_ids": credential_ids,
        "rp_id": "kepr",
    });
    let mut child = Command::new(&helper)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {helper}: {e}"))?;
    let stdin = child.stdin.as_mut().ok_or("helper: no stdin")?;
    serde_json::to_writer(&mut *stdin, &input).map_err(|e| format!("helper write: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("helper wait: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("helper exit {}: {}", out.status, stderr.trim()));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("helper output: {e}"))
}
