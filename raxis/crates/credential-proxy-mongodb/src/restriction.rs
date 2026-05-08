//! Restriction enforcement for the MongoDB proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §4.4` "MongoDB
//! restrictions". V2 supports `allow_read_only` only — the
//! richer surface (`forbidden_collections`, `max_documents`,
//! `op_timeout_ms`) is documented in the spec and lands when the
//! BSON doc-walker matures.

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// If true, only read commands (`find`, `aggregate`, `count`,
    /// `distinct`, `listCollections`, `listIndexes`, `listDatabases`,
    /// `dbStats`, `collStats`, `hello`, `isMaster`, `ping`, `buildInfo`,
    /// `serverStatus`, `getMore`, `connectionStatus`, `whatsmyuri`)
    /// are allowed; everything else (insert/update/delete/
    /// findAndModify/createCollection/etc.) is rejected with
    /// `{ ok: 0, code: 13, codeName: "Unauthorized" }`.
    #[serde(default)]
    pub allow_read_only: bool,
}

impl Restrictions {
    /// Convenience constructor for tests.
    pub const fn read_only() -> Self {
        Self { allow_read_only: true }
    }

    /// Returns `true` if `command_name` (case-sensitive — MongoDB
    /// command names are camelCase) must be blocked under this
    /// restriction set.
    pub fn is_blocked(&self, command_name: &str) -> bool {
        if !self.allow_read_only { return false; }
        !is_read_command(command_name)
    }
}

/// Returns `true` if `name` is a known MongoDB read-only command.
/// Source: <https://www.mongodb.com/docs/manual/reference/command/>
/// and the `read` action category.
pub fn is_read_command(name: &str) -> bool {
    matches!(
        name,
        // Query commands.
        | "find"
        | "aggregate"
        | "count"
        | "distinct"
        | "geoSearch"
        | "getMore"
        | "parallelCollectionScan"
        // Server / catalog inspection.
        | "hello"
        | "isMaster"
        | "ismaster"
        | "ping"
        | "buildInfo"
        | "buildinfo"
        | "serverStatus"
        | "hostInfo"
        | "connectionStatus"
        | "whatsmyuri"
        | "listCollections"
        | "listIndexes"
        | "listDatabases"
        | "dbStats"
        | "collStats"
        | "explain"
        | "validate"
        | "currentOp"
        | "getParameter"
        | "saslStart"
        | "saslContinue"
        | "logout"
        | "endSessions"
        | "killCursors"
        | "killAllSessions"
        | "killAllSessionsByPattern"
        | "killSessions"
        | "abortTransaction"
        | "commitTransaction"
        | "startSession"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_blocks_writes() {
        let r = Restrictions::read_only();
        assert!(!r.is_blocked("find"));
        assert!(!r.is_blocked("aggregate"));
        assert!(!r.is_blocked("hello"));
        assert!( r.is_blocked("insert"));
        assert!( r.is_blocked("update"));
        assert!( r.is_blocked("delete"));
        assert!( r.is_blocked("findAndModify"));
        assert!( r.is_blocked("createCollection"));
    }

    #[test]
    fn unrestricted_blocks_nothing() {
        let r = Restrictions::default();
        assert!(!r.is_blocked("insert"));
    }
}
