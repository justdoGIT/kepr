// daemon_recordsx/ — the `records` ticket batch, daemon side: attachments
// (T5.03), record field shapes (T5.05), linked records (T11.6), record
// convert (T11.7), health ignores (T11.23). Requests arrive as `Request::Records` via daemon_extra.rs.
// (`daemon_records.rs` already holds the P5.1 typed records, hence the x.)
//
// Hooks other modules call:
//   handle_set (daemon_handlers.rs)     carry_over: keep the attachments
//   daemon_history::purge / purge_in    purge_attachments(_in): a deleted,
//                                       purged or expired value's chunks
//   daemon_store trash                  move_attachments: into / out of
//                                       the trash with the value
//   daemon_store verify                 verify_attachments
//   daemon_records::validate            check_field
//   daemon_records::handle_record_set   check_links
//   daemon_health::handle_health        apply_health_ignores

mod attach;
mod attach_read;
mod chunks;
mod convert;
mod fields;
mod health_ignore;
mod links;

use kepr_core::protocol::Response;
use kepr_core::protocol_records::RecordsRequest;

pub use fields::check_field;
pub use health_ignore::apply as apply_health_ignores;
pub use links::check_links;

pub use chunks::{
    carry_over, move_all as move_attachments, purge as purge_attachments,
    purge_in as purge_attachments_in, verify as verify_attachments,
};

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, r: RecordsRequest) -> Response {
    match r {
        RecordsRequest::AttachPut {
            name,
            file,
            upload,
            index,
            chunk,
            last,
        } => attach::handle_put(
            uid,
            username,
            &name,
            attach::Put {
                file: &file,
                upload: upload.as_deref(),
                index,
                chunk: &chunk,
                last,
            },
        ),
        RecordsRequest::AttachGet { name, file, index } => {
            attach_read::handle_get((uid, peer_pid), username, &name, &file, index)
        }
        RecordsRequest::AttachList { name } => attach_read::handle_list(uid, username, &name),
        RecordsRequest::AttachRemove { name, file } => {
            attach_read::handle_remove(uid, username, &name, &file)
        }
        RecordsRequest::RecordConvert {
            name,
            record_type,
            fields,
        } => convert::handle_convert(uid, username, &name, &record_type, &fields),
        RecordsRequest::HealthIgnore { name, kinds, clear } => {
            health_ignore::handle_ignore(uid, username, &name, &kinds, clear)
        }
    }
}
