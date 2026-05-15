// raxis-cli::closeness — "did you mean" helper for unknown subcommands.
//
// Normative reference: cli-ceremony.md §4.1 (subcommand catalog) and
// cli-readonly.md §5.5 (read-only subcommand catalog). When the
// operator types a subcommand we don't recognise, we want to surface
// the closest known commands so they can self-correct without grepping
// `--help`. Mirrors the UX of `git`'s `did you mean...` prompt.
//
// Algorithm
// =========
//
// Damerau–Levenshtein (with one transposition counted as cost 1)
// ranking, with two threshold rules:
//
//   1. Exact prefix matches always win — typing `raxis ce` should
//      surface `cert` (and not, say, `escalation` which is closer
//      by raw edit distance). Prefix matches are emitted FIRST in
//      the suggestion list, in the order the candidate dictionary
//      provided them (so the cli's canonical command order is
//      preserved).
//
//   2. After prefixes, candidates whose distance to the input is
//      ≤ `max_distance(input.len())` are appended, sorted by
//      distance ascending then by original-order. The threshold
//      grows with input length so single-letter inputs don't
//      generate noise:
//
//        | len | max_distance |
//        |  1  |      0       |  (only exact prefix)
//        |  2  |      1       |
//        |  3  |      1       |
//        |  4  |      2       |
//        |  5+ |      3       |
//
//   3. We cap the suggestion list at `MAX_SUGGESTIONS = 5` so the
//      operator-facing message stays short. Empty suggestion list
//      is a valid outcome — caller should still print the "unknown
//      subcommand" line.
//
// Comparison is case-sensitive on the assumption that subcommands
// are always lowercase ASCII (verify-chain, submit plan, …) — the
// CLI never accepts mixed-case forms today, so a case-insensitive
// match would only succeed on operator typos like `RAXIS CERT`,
// which we'd rather surface as a usage error than auto-correct.

const MAX_SUGGESTIONS: usize = 5;

/// Returns the closest known commands to `input`, ranked.
///
/// `candidates` should be the canonical list of subcommand names in
/// the order they should appear in tied results (typically the order
/// from the CLI's `match` table or the `--help` output).
///
/// The return value is a `Vec<&'a str>` borrowed from `candidates`
/// so the caller can format suggestions without further allocation.
/// Empty when nothing is close enough; capped at `MAX_SUGGESTIONS`.
pub fn did_you_mean<'a>(input: &str, candidates: &'a [&'a str]) -> Vec<&'a str> {
    if input.is_empty() || candidates.is_empty() {
        return Vec::new();
    }

    let threshold = max_distance(input.len());

    // Pass 1: exact prefix matches in candidate order.
    let mut prefixes: Vec<&str> = candidates
        .iter()
        .copied()
        .filter(|c| c.starts_with(input) && *c != input)
        .collect();

    // Pass 2: distance-bounded matches, sorted (distance, original idx).
    let mut by_distance: Vec<(usize, usize, &str)> = candidates
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, c)| !c.starts_with(input)) // dedupe with pass 1
        .map(|(idx, c)| (damerau_levenshtein(input, c), idx, c))
        .filter(|(d, _, _)| *d <= threshold)
        .collect();
    by_distance.sort_by_key(|&(d, idx, _)| (d, idx));

    prefixes.extend(by_distance.into_iter().map(|(_, _, c)| c));
    prefixes.truncate(MAX_SUGGESTIONS);
    prefixes
}

/// Format `did_you_mean` output as a single human-friendly line.
///
/// Empty list -> `None` (caller should not print anything extra).
/// 1 entry  -> `Did you mean `cert`?`
/// 2 entries -> `Did you mean `cert` or `escalation`?`
/// 3+        -> `Did you mean one of: `cert`, `escalation`, `epoch`?`
pub fn format_suggestion(suggestions: &[&str]) -> Option<String> {
    match suggestions {
        [] => None,
        [one] => Some(format!("Did you mean `{one}`?")),
        [a, b] => Some(format!("Did you mean `{a}` or `{b}`?")),
        many => {
            let joined = many
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ");
            Some(format!("Did you mean one of: {joined}?"))
        }
    }
}

/// Build the full `"unknown <kind>"` usage message a `match`-arm error
/// branch should return, including the suggestion line when one is
/// available.
///
/// `kind` should be a noun like `"subcommand"`, `"cert sub-command"`,
/// `"plan sub-command"`. The output looks like:
///
/// ```text
/// unknown subcommand: "ceert". Did you mean `cert`?
/// ```
///
/// or, when nothing is close enough:
///
/// ```text
/// unknown subcommand: "xyzzy"
/// ```
pub fn unknown_with_suggestion(kind: &str, input: &str, candidates: &[&str]) -> String {
    let mut msg = format!("unknown {kind}: {input:?}");
    if let Some(line) = format_suggestion(&did_you_mean(input, candidates)) {
        msg.push_str(". ");
        msg.push_str(&line);
    }
    msg
}

// ---------------------------------------------------------------------------
// Distance threshold by input length
// ---------------------------------------------------------------------------

fn max_distance(len: usize) -> usize {
    match len {
        0 | 1 => 0,
        2 | 3 => 1,
        4 => 2,
        _ => 3,
    }
}

// ---------------------------------------------------------------------------
// Damerau–Levenshtein (optimal-string-alignment variant)
// ---------------------------------------------------------------------------
//
// OSA distance is the textbook DP variant that allows a single
// transposition to count as one edit (so "ot" -> "to" has distance 1
// rather than 2). We use it because operator typos are dominated by
// adjacent-key transpositions ("apporve" / "approve") and 1-letter
// substitutions; pure Levenshtein would put both at distance 2 and
// suppress the suggestion under our short-input thresholds.

fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());

    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }

    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in dp.iter_mut().enumerate().take(n + 1) {
        row[0] = i;
    }
    for j in 0..=m {
        dp[0][j] = j;
    }

    for i in 1..=n {
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let mut v = (dp[i - 1][j] + 1) // deletion
                .min(dp[i][j - 1] + 1) // insertion
                .min(dp[i - 1][j - 1] + cost); // substitution
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(dp[i - 2][j - 2] + 1); // transposition
            }
            dp[i][j] = v;
        }
    }
    dp[n][m]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Distance helper ────────────────────────────────────────────────────

    #[test]
    fn damerau_distance_is_zero_for_identical_strings() {
        assert_eq!(damerau_levenshtein("cert", "cert"), 0);
    }

    #[test]
    fn damerau_distance_handles_empty_inputs() {
        assert_eq!(damerau_levenshtein("", ""), 0);
        assert_eq!(damerau_levenshtein("", "abc"), 3);
        assert_eq!(damerau_levenshtein("abc", ""), 3);
    }

    #[test]
    fn damerau_counts_one_substitution() {
        assert_eq!(damerau_levenshtein("kiln", "kill"), 1);
    }

    #[test]
    fn damerau_counts_one_insertion_and_one_deletion() {
        assert_eq!(damerau_levenshtein("ert", "cert"), 1);
        assert_eq!(damerau_levenshtein("certs", "cert"), 1);
    }

    #[test]
    fn damerau_treats_adjacent_transposition_as_distance_one() {
        // Pure Levenshtein would say 2 here.
        assert_eq!(damerau_levenshtein("ot", "to"), 1);
        assert_eq!(damerau_levenshtein("apporve", "approve"), 1);
    }

    // ── Threshold ──────────────────────────────────────────────────────────

    #[test]
    fn max_distance_grows_with_input_length() {
        assert_eq!(max_distance(0), 0);
        assert_eq!(max_distance(1), 0);
        assert_eq!(max_distance(2), 1);
        assert_eq!(max_distance(3), 1);
        assert_eq!(max_distance(4), 2);
        assert_eq!(max_distance(5), 3);
        assert_eq!(max_distance(20), 3);
    }

    // ── did_you_mean: prefix matches ──────────────────────────────────────

    #[test]
    fn did_you_mean_returns_prefix_matches_first_in_candidate_order() {
        // Three candidates start with "ce" — the function must keep
        // the dictionary's order rather than re-sorting alphabetically.
        let cands = ["cert", "cesium", "celery", "delegation"];
        assert_eq!(did_you_mean("ce", &cands), vec!["cert", "cesium", "celery"],);
    }

    #[test]
    fn did_you_mean_excludes_exact_match_from_prefix_pass() {
        // Operator typed exactly "cert"; that's not a typo and there's
        // nothing to suggest.
        assert!(did_you_mean("cert", &["cert"]).is_empty());
    }

    // ── did_you_mean: distance matches ────────────────────────────────────

    #[test]
    fn did_you_mean_finds_one_letter_typo_for_short_command() {
        // "ceert" -> "cert" is one insertion; falls within len-5 / d-3.
        let cands = ["cert", "session", "delegation"];
        assert_eq!(did_you_mean("ceert", &cands), vec!["cert"]);
    }

    #[test]
    fn did_you_mean_finds_transposed_letters() {
        // "appoorve" vs "approve" — one transposition (oo<->ro)?
        // Use a cleaner case: "apporve" vs "approve" — distance 1.
        let cands = ["approve", "abort", "advance"];
        assert_eq!(did_you_mean("apporve", &cands), vec!["approve"]);
    }

    #[test]
    fn did_you_mean_filters_far_candidates() {
        // "xyz" is distance ≥ 3 from every candidate; len-3 only allows
        // distance 1.
        let cands = ["cert", "session", "delegation"];
        assert!(did_you_mean("xyz", &cands).is_empty());
    }

    #[test]
    fn did_you_mean_caps_at_max_suggestions() {
        let cands = [
            "approve",
            "approved",
            "approver",
            "approves",
            "approveing",
            "approvee",
            "approva",
        ];
        let got = did_you_mean("approv", &cands);
        assert!(got.len() <= MAX_SUGGESTIONS);
    }

    #[test]
    fn did_you_mean_is_empty_on_empty_input_or_candidate_list() {
        assert!(did_you_mean("", &["cert"]).is_empty());
        assert!(did_you_mean("cert", &[]).is_empty());
    }

    // ── did_you_mean: ordering when prefix + distance both apply ─────────

    #[test]
    fn did_you_mean_emits_prefix_matches_before_distance_matches() {
        // "se" prefix-matches "session" and "sessions"; "be" is
        // distance 1 from "se" (one substitution) so it should appear
        // AFTER the two prefixes, not interleaved with them.
        let cands = ["session", "sessions", "be"];
        let got = did_you_mean("se", &cands);
        assert_eq!(got, vec!["session", "sessions", "be"]);
    }

    #[test]
    fn did_you_mean_drops_candidates_outside_the_distance_threshold() {
        // Input is len-3 → threshold = 1. "delegation" is way beyond
        // and is also not a prefix; it must be filtered out entirely.
        let cands = ["car", "delegation"];
        let got = did_you_mean("cat", &cands);
        assert_eq!(got, vec!["car"]);
    }

    // ── format_suggestion ─────────────────────────────────────────────────

    #[test]
    fn format_suggestion_returns_none_for_empty_list() {
        assert_eq!(format_suggestion(&[]), None);
    }

    #[test]
    fn format_suggestion_uses_singular_phrasing_for_one_candidate() {
        assert_eq!(
            format_suggestion(&["cert"]).as_deref(),
            Some("Did you mean `cert`?"),
        );
    }

    #[test]
    fn format_suggestion_uses_or_for_two_candidates() {
        assert_eq!(
            format_suggestion(&["cert", "escalation"]).as_deref(),
            Some("Did you mean `cert` or `escalation`?"),
        );
    }

    #[test]
    fn format_suggestion_uses_one_of_for_three_or_more() {
        assert_eq!(
            format_suggestion(&["cert", "escalation", "epoch"]).as_deref(),
            Some("Did you mean one of: `cert`, `escalation`, `epoch`?"),
        );
    }

    // ── unknown_with_suggestion ───────────────────────────────────────────

    #[test]
    fn unknown_with_suggestion_appends_did_you_mean_when_match_found() {
        let msg =
            unknown_with_suggestion("subcommand", "ceert", &["cert", "session", "delegation"]);
        assert_eq!(msg, "unknown subcommand: \"ceert\". Did you mean `cert`?");
    }

    #[test]
    fn unknown_with_suggestion_omits_did_you_mean_when_nothing_is_close() {
        let msg =
            unknown_with_suggestion("subcommand", "xyzzy", &["cert", "session", "delegation"]);
        assert_eq!(msg, "unknown subcommand: \"xyzzy\"");
    }

    #[test]
    fn unknown_with_suggestion_handles_kind_with_spaces() {
        let msg = unknown_with_suggestion(
            "cert sub-command",
            "mintt",
            &[
                "mint",
                "mint-emergency",
                "show",
                "verify",
                "list",
                "install",
            ],
        );
        assert!(
            msg.starts_with("unknown cert sub-command: \"mintt\""),
            "msg = {msg:?}",
        );
        assert!(msg.contains("`mint`"), "msg = {msg:?}");
    }
}
