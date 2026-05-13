// Fake kernel binary that exits cleanly (code 0). The supervisor
// MUST NOT restart this — `Outcome::CleanExit{0}` is not
// restart-eligible per `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`.

fn main() {
    std::process::exit(0);
}
