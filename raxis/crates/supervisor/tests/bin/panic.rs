// Fake kernel binary that panics (`std::process::exit(101)` —
// the standard Rust panic exit code, used here without actually
// `panic!`'ing so we don't get a backtrace dump cluttering the
// test log). Exercises the supervisor's `Outcome::PanicAbort`
// decision path.

fn main() {
    std::process::exit(101);
}
