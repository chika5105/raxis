// raxis-kernel::notifications::handler — per-channel-kind handlers.
//
// v1 ships handlers for `Shell` and `File` only. Both are
// operationally identical (append a JSON line to a file) so they share
// `handler::file::deliver`. `Email` and `Webhook` channels are
// schema-only in v1 — see `notifications::dispatch_one` for how they
// short-circuit to `DeliveryError::UnimplementedV1`.

pub mod file;
