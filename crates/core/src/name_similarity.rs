//! Cheap, ecosystem-agnostic detection of package names that are
//! close-but-not-equal to a curated list of popular targets — the
//! classic typosquat (`axois` → `axios`) and homoglyph (Cyrillic
//! `а` for Latin `a`) attack surface.
//!
//! Two checks compose into [`classify`]:
//!
//! 1. **Damerau-Levenshtein distance** ≤ 1 to a popular name, where
//!    distance 0 (exact match) is intentionally *not* a finding —
//!    that's just `axios` itself. Distance 1 covers a single
//!    insertion, deletion, substitution, or adjacent-transposition.
//!
//! 2. **Homoglyph normalisation**: fold a small set of well-known
//!    confusable Unicode codepoints to ASCII and re-compare. If the
//!    normalised form is an exact match to a popular name but the
//!    raw form isn't, the candidate is using lookalike characters.
//!
//! The popular-name list is intentionally compact. It is *not* a
//! complete top-N-by-downloads ranking; it's a hand-picked set
//! optimised for *attacker value* — packages that show up in
//! transitive trees everywhere and whose name shape is short
//! enough that a distance-1 typo is a plausible attack. Long,
//! descriptive names (`@babel/preset-typescript`) are excluded
//! because the distance-1 check produces too many benign collisions
//! for them.
//!
//! The data is a static `&[&str]`, sorted, with one allocation per
//! check (the lowercase fold of the candidate). Keeping it inline
//! makes the dependency vendorable and means the signal works in
//! offline mode.

/// Result of comparing a candidate package name against the popular
/// list. `Ok` is the safe path; `Suspicious` is the only outcome
/// callers act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// Either the name is a popular package itself, or it is far
    /// enough from every popular name to be unambiguous.
    Ok,
    /// The candidate is a near-miss for a popular package. `kind`
    /// distinguishes a typo from a homoglyph; `target` is the
    /// popular name it resembles.
    Suspicious { kind: SquatKind, target: String },
}

/// Which similarity rule fired. Carried into the reason so audit
/// logs can distinguish honest typos from deliberate lookalikes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SquatKind {
    /// Damerau-Levenshtein distance == 1 against the target.
    Typo,
    /// After folding confusable Unicode codepoints to ASCII the
    /// normalised form matched the target exactly, but the raw
    /// form did not.
    Homoglyph,
}

impl SquatKind {
    /// Stable kebab-case identifier suitable for the `pattern` field
    /// of a signal/reason — keeps wire format independent of the
    /// `Debug` derive.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Typo => "typo",
            Self::Homoglyph => "homoglyph",
        }
    }
}

/// Compact list of high-value typosquat targets. Sorted by name so
/// `binary_search` is O(log n) for the exact-match check. Adding
/// names here is cheap; removing them after a typosquat advisory
/// references one is a breaking change for users' allow-lists, so
/// be conservative.
const POPULAR: &[&str] = &[
    "axios",
    "babel",
    "chalk",
    "commander",
    "debug",
    "dotenv",
    "express",
    "fastify",
    "glob",
    "got",
    "jest",
    "lodash",
    "minimist",
    "moment",
    "mongoose",
    "next",
    "node-fetch",
    "nodemon",
    "prettier",
    "react",
    "redux",
    "request",
    "rxjs",
    "semver",
    "tslib",
    "typescript",
    "underscore",
    "uuid",
    "vue",
    "webpack",
    "yargs",
    "zod",
];

/// Curated allow-list of well-known legitimate packages whose names
/// happen to land within Damerau-Levenshtein distance 1 of an entry
/// in [`POPULAR`]. Without this list the `ulid` → `uuid`,
/// `nuxt` → `next`, and `preact` → `react` distance-1 collisions
/// fire as typo squats on every real-world scan, drowning out the
/// genuine catches.
///
/// Sorted for `binary_search`. Names here are *only* exempt from
/// classification — they are not promoted to typosquat targets.
/// Add a name only when:
///
///   * it has a non-trivial install footprint on npm
///     (rule of thumb: ≥100 k weekly downloads), AND
///   * a quick search of `npm-advisory-db` shows no historical
///     advisory naming it as a squatter.
const ALLOWLIST: &[&str] = &[
    "fastly",
    "nuxt",
    "preact",
    "redis",
    "ulid",
    "vitest",
];

/// Top-level entry point. Returns [`Classification::Ok`] for unscoped
/// names that are either exact matches or sufficiently far from every
/// popular name; otherwise the variant carries the suspected target
/// and rule. Scoped names (`@scope/pkg`) are *not* classified — the
/// `@scope/` prefix is intentional namespacing and the typosquat
/// risk model is fundamentally different.
#[must_use]
pub fn classify(name: &str) -> Classification {
    if name.starts_with('@') {
        return Classification::Ok;
    }
    let lower = name.to_ascii_lowercase();

    // 1. Exact match → it *is* the popular package; not suspicious.
    if POPULAR.binary_search(&lower.as_str()).is_ok() {
        return Classification::Ok;
    }

    // 1b. Curated allow-list of well-known packages that collide
    //     with POPULAR within distance 1. See [`ALLOWLIST`].
    if ALLOWLIST.binary_search(&lower.as_str()).is_ok() {
        return Classification::Ok;
    }

    // 2. Homoglyph fold — only meaningful when the raw name had at
    //    least one non-ASCII char that we know how to fold.
    let folded = fold_confusables(&lower);
    if folded != lower && POPULAR.binary_search(&folded.as_str()).is_ok() {
        return Classification::Suspicious {
            kind: SquatKind::Homoglyph,
            target: folded,
        };
    }

    // 3. Distance-1 sweep. Skip names that are very short — for a
    //    3-character name the distance-1 set is huge and dominated
    //    by unrelated packages.
    if lower.len() >= 4 {
        for popular in POPULAR {
            if popular.len().abs_diff(lower.len()) > 1 {
                continue;
            }
            if damerau_levenshtein_at_most_one(&lower, popular) {
                return Classification::Suspicious {
                    kind: SquatKind::Typo,
                    target: (*popular).to_string(),
                };
            }
        }
    }

    Classification::Ok
}

/// Fast specialised Damerau-Levenshtein that only returns true when
/// the distance is exactly 1 (zero is handled by the equality check
/// the caller already did). This avoids constructing the full DP
/// table and is plenty for our use — distance-2 typos are too
/// noisy to act on at registry scale anyway.
fn damerau_levenshtein_at_most_one(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let av: Vec<char> = a.chars().collect();
    let bv: Vec<char> = b.chars().collect();
    let (alen, blen) = (av.len(), bv.len());
    let diff = alen.abs_diff(blen);
    if diff > 1 {
        return false;
    }

    if alen == blen {
        // Same length: must be either a single substitution OR an
        // adjacent transposition.
        let mut diffs = 0usize;
        let mut first_diff: Option<usize> = None;
        for i in 0..alen {
            if av[i] != bv[i] {
                diffs += 1;
                if diffs > 2 {
                    return false;
                }
                if first_diff.is_none() {
                    first_diff = Some(i);
                }
            }
        }
        if diffs == 1 {
            return true;
        }
        if diffs == 2 {
            // Adjacent transposition: the two diff positions must
            // be neighbours and the chars must swap cleanly.
            if let Some(i) = first_diff {
                if i + 1 < alen && av[i] == bv[i + 1] && av[i + 1] == bv[i] {
                    // Confirm no further diffs after i+1.
                    return av.iter().skip(i + 2).eq(bv.iter().skip(i + 2));
                }
            }
        }
        return false;
    }

    // Off-by-one length: must be a single insertion/deletion. Walk
    // both strings in lockstep, allowing one skip on the longer side.
    let (short, long) = if alen < blen { (&av, &bv) } else { (&bv, &av) };
    let mut i = 0usize;
    let mut j = 0usize;
    let mut skipped = false;
    while i < short.len() && j < long.len() {
        if short[i] == long[j] {
            i += 1;
            j += 1;
        } else if skipped {
            return false;
        } else {
            skipped = true;
            j += 1; // skip a char in the longer string
        }
    }
    // Any remaining char in `long` is the (single) skipped char.
    true
}

/// Folds a small fixed set of well-known confusable codepoints to
/// their ASCII look-alike. The list is intentionally tiny — adding
/// every Unicode confusable would inflate binary size for marginal
/// benefit. These are the codepoints that have actually appeared in
/// known npm/PyPI typosquat advisories.
#[allow(clippy::match_same_arms)]
// Several arms intentionally fold to the same target ASCII char
// (Cyrillic + Greek + fullwidth all map to `a`/`o`/`e`); merging
// the patterns would obscure the per-codepoint provenance.
fn fold_confusables(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            // Cyrillic small letters that look identical to ASCII
            'а' => 'a', // U+0430
            'е' => 'e', // U+0435
            'о' => 'o', // U+043E
            'р' => 'p', // U+0440
            'с' => 'c', // U+0441
            'у' => 'y', // U+0443
            'х' => 'x', // U+0445
            // Greek omicron / iota that look like Latin
            'ο' => 'o', // U+03BF
            'ι' => 'i', // U+03B9
            // Fullwidth Latin (sometimes used in punycode-like attacks)
            'ａ' => 'a', // U+FF41
            'ｅ' => 'e', // U+FF45
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popular_list_is_sorted_for_binary_search() {
        let mut sorted = POPULAR.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, POPULAR.to_vec(), "POPULAR must be sorted");
    }

    #[test]
    fn exact_match_is_ok() {
        assert_eq!(classify("axios"), Classification::Ok);
        assert_eq!(classify("lodash"), Classification::Ok);
    }

    #[test]
    fn distant_name_is_ok() {
        assert_eq!(classify("my-internal-tool"), Classification::Ok);
    }

    #[test]
    fn typo_substitution_flagged() {
        match classify("axois") {
            Classification::Suspicious { kind, target } => {
                assert_eq!(kind, SquatKind::Typo);
                assert_eq!(target, "axios");
            }
            Classification::Ok => panic!("expected suspicious, got Ok"),
        }
    }

    #[test]
    fn typo_transposition_flagged() {
        // axios -> axois (transpose i,o)
        if let Classification::Suspicious { kind, target } = classify("aixos") {
            assert_eq!(kind, SquatKind::Typo);
            assert_eq!(target, "axios");
        } else {
            panic!("expected suspicious for transposition");
        }
    }

    #[test]
    fn typo_insertion_flagged() {
        if let Classification::Suspicious { kind, target } = classify("axioss") {
            assert_eq!(kind, SquatKind::Typo);
            assert_eq!(target, "axios");
        } else {
            panic!("expected suspicious for insertion");
        }
    }

    #[test]
    fn typo_deletion_flagged() {
        if let Classification::Suspicious { kind, target } = classify("xios") {
            assert_eq!(kind, SquatKind::Typo);
            assert_eq!(target, "axios");
        } else {
            panic!("expected suspicious for deletion");
        }
    }

    #[test]
    fn very_short_names_dont_explode() {
        // 3-char names below the threshold — don't flag noise.
        assert_eq!(classify("got"), Classification::Ok); // exact
        assert_eq!(classify("rxz"), Classification::Ok); // distance ≤1 from rxjs but too short
    }

    #[test]
    fn scoped_names_skipped() {
        assert_eq!(classify("@scope/axois"), Classification::Ok);
    }

    #[test]
    fn homoglyph_cyrillic_a_in_axios() {
        // U+0430 CYRILLIC SMALL LETTER A in place of ASCII 'a'.
        let name = "\u{0430}xios";
        match classify(name) {
            Classification::Suspicious { kind, target } => {
                assert_eq!(kind, SquatKind::Homoglyph);
                assert_eq!(target, "axios");
            }
            Classification::Ok => panic!("expected homoglyph, got Ok"),
        }
    }

    #[test]
    fn distance_two_not_flagged() {
        // axios vs axxxs — distance 2, must not fire.
        assert_eq!(classify("axxxs"), Classification::Ok);
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(classify("AXIOS"), Classification::Ok);
        if let Classification::Suspicious { target, .. } = classify("AXOIS") {
            assert_eq!(target, "axios");
        } else {
            panic!();
        }
    }

    #[test]
    fn allowlisted_packages_are_not_flagged() {
        // Each of these is exactly distance-1 from a POPULAR entry
        // and would otherwise be classified as a typosquat:
        //   ulid   ↔ uuid   (substitution at index 1)
        //   nuxt   ↔ next   (substitution at index 1)
        //   preact ↔ react  (insertion of leading 'p')
        for legit in ["ulid", "nuxt", "preact", "redis", "vitest", "fastly"] {
            assert_eq!(
                classify(legit),
                Classification::Ok,
                "{legit} must not be flagged as a squat"
            );
        }
    }

    #[test]
    fn allowlist_is_sorted_for_binary_search() {
        let mut sorted = super::ALLOWLIST.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, super::ALLOWLIST);
    }
}
