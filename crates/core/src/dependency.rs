//! Normalised, ecosystem-agnostic representation of a resolved dependency.

use serde::{Deserialize, Serialize};

/// Package ecosystem identifiers. New ecosystems should be added here only
/// once an adapter and signal provider for them exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pnpm,
    Yarn,
    /// PyPI (Python Package Index).
    Pypi,
}

impl Ecosystem {
    /// Returns the package-manager-neutral registry family. `npm`, `pnpm`,
    /// and `yarn` all consume the npm registry, so policy and signals can
    /// usually treat them uniformly.
    #[must_use]
    pub fn registry_family(self) -> RegistryFamily {
        match self {
            Self::Npm | Self::Pnpm | Self::Yarn => RegistryFamily::Npm,
            Self::Pypi => RegistryFamily::Pypi,
        }
    }
}

/// Registry family — a coarser grouping than [`Ecosystem`] used by
/// policy matchers. Multiple package managers (e.g. `npm`, `pnpm`,
/// `yarn`) consume the same registry family and therefore share
/// allowlists.
///
/// `Pypi` is reserved for the PyPI adapter (see ROADMAP M8); its
/// presence here lets policy authors write forward-compatible
/// `pypi:...` entries today even though no PyPI adapter is shipped
/// yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryFamily {
    Npm,
    /// PyPI registry family.
    Pypi,
}

impl RegistryFamily {
    /// Stable lowercase token used as the YAML / JSON prefix in
    /// [`EcosystemMatcher`] (`npm:lodash`, `pypi:requests`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
        }
    }
}

impl std::str::FromStr for RegistryFamily {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "npm" => Ok(Self::Npm),
            "pypi" => Ok(Self::Pypi),
            _ => Err(()),
        }
    }
}

/// Package selector used in policy allowlists (`scripts.allow`,
/// `defaults.nameSquatAllow`).
///
/// Accepts an optional `family:` prefix:
///
/// * Bare `lodash` — matches any registry family. This is the default
///   for back-compat with v1 policies and the right shape for
///   single-ecosystem projects.
/// * Prefixed `npm:lodash` — matches only deps in the `npm` family
///   (i.e. resolved by `npm`, `pnpm`, or `yarn`).
/// * Prefixed `pypi:requests` — matches only PyPI deps.
///
/// Scoped npm names (`@scope/name`, `npm:@scope/name`) are accepted
/// in both forms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EcosystemMatcher {
    /// `Some(family)` restricts the match to a single registry
    /// family; `None` matches any family (back-compat).
    pub family: Option<RegistryFamily>,
    /// Exact package name (no version). Compared verbatim.
    pub name: String,
}

impl EcosystemMatcher {
    /// Construct a bare (family-agnostic) matcher.
    #[must_use]
    pub fn bare(name: impl Into<String>) -> Self {
        Self {
            family: None,
            name: name.into(),
        }
    }

    /// Construct a family-scoped matcher.
    #[must_use]
    pub fn scoped(family: RegistryFamily, name: impl Into<String>) -> Self {
        Self {
            family: Some(family),
            name: name.into(),
        }
    }

    /// True when the matcher applies to a `(family, name)` pair.
    /// Bare matchers ignore the family.
    #[must_use]
    pub fn matches(&self, family: RegistryFamily, name: &str) -> bool {
        self.name == name && self.family.is_none_or(|f| f == family)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EcosystemMatcherParseError {
    #[error("empty matcher")]
    Empty,
    #[error("unknown registry family `{family}` in `{full}`; valid: npm, pypi")]
    UnknownFamily { family: String, full: String },
    #[error("missing package name after `{family}:`")]
    MissingName { family: String },
}

impl std::str::FromStr for EcosystemMatcher {
    type Err = EcosystemMatcherParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(EcosystemMatcherParseError::Empty);
        }
        // Look for a `family:` prefix in the segment *before* any `/`.
        // Scoped npm names like `@scope/name` carry no colon in the
        // scope segment, so the only colon we care about is one that
        // sits before the first slash (or in the whole string when
        // there's no slash).
        let head_end = s.find('/').unwrap_or(s.len());
        let head = &s[..head_end];
        let Some((family_str, _)) = head.split_once(':') else {
            return Ok(Self::bare(s));
        };
        let after = &s[family_str.len() + 1..];
        if after.is_empty() {
            return Err(EcosystemMatcherParseError::MissingName {
                family: family_str.to_string(),
            });
        }
        let family = family_str.parse::<RegistryFamily>().map_err(|()| {
            EcosystemMatcherParseError::UnknownFamily {
                family: family_str.to_string(),
                full: s.to_string(),
            }
        })?;
        Ok(Self::scoped(family, after))
    }
}

impl std::fmt::Display for EcosystemMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.family {
            Some(family) => write!(f, "{}:{}", family.as_str(), self.name),
            None => f.write_str(&self.name),
        }
    }
}

impl Serialize for EcosystemMatcher {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EcosystemMatcher {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl schemars::JsonSchema for EcosystemMatcher {
    fn schema_name() -> String {
        "EcosystemMatcher".to_string()
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            ..Default::default()
        };
        schema.metadata().description = Some(
            "Package selector. Bare name (`lodash`) matches any registry family; \
             prefixed name (`npm:lodash`, `pypi:requests`) matches only that family. \
             Scoped npm names (`@scope/name`) are accepted in both forms."
                .into(),
        );
        schema.into()
    }
}

/// Subresource integrity, as recorded in lockfiles.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Integrity(pub String);

impl Integrity {
    #[must_use]
    pub fn algorithm(&self) -> Option<&str> {
        self.0.split_once('-').map(|(alg, _)| alg)
    }
}

/// Where the dependency was acquired from. Anything other than `Registry`
/// or `Pypi` (both first-party registry sources) is considered "exotic"
/// and can be blocked by policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    Registry {
        url: String,
    },
    Git {
        url: String,
        reference: Option<String>,
    },
    Tarball {
        url: String,
    },
    File {
        path: String,
    },
    GithubShortcut {
        spec: String,
    },
    Workspace,
    /// PyPI artifact — sdist (`.tar.gz`) or wheel (`.whl`) hosted on
    /// `files.pythonhosted.org` (or a configured index mirror).
    /// Treated as non-exotic alongside `Registry`.
    Pypi {
        url: String,
    },
}

impl Source {
    #[must_use]
    pub fn is_exotic(&self) -> bool {
        !matches!(
            self,
            Self::Registry { .. } | Self::Workspace | Self::Pypi { .. }
        )
    }
}

/// A dependency after lockfile resolution. Adapters normalise their
/// ecosystem-specific lockfile shape into this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDependency {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub integrity: Option<Integrity>,
    pub source: Source,
    pub direct: bool,
    /// Path through the dependency tree that pulled this in. Empty for
    /// direct deps. Each entry is a `name@version` pair.
    pub requested_by: Vec<String>,
}

impl ResolvedDependency {
    /// Stable identity used as a cache key and in `installguard.lock`.
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "{}/{}@{}",
            self.ecosystem.registry_family().as_str(),
            self.name,
            self.version
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_matcher_keeps_name_and_no_family() {
        let m: EcosystemMatcher = "lodash".parse().unwrap();
        assert_eq!(m, EcosystemMatcher::bare("lodash"));
        assert_eq!(m.to_string(), "lodash");
    }

    #[test]
    fn parse_npm_prefix_scopes_to_npm_family() {
        let m: EcosystemMatcher = "npm:lodash".parse().unwrap();
        assert_eq!(m, EcosystemMatcher::scoped(RegistryFamily::Npm, "lodash"));
        assert_eq!(m.to_string(), "npm:lodash");
    }

    #[test]
    fn parse_pypi_prefix_scopes_to_pypi_family() {
        let m: EcosystemMatcher = "pypi:requests".parse().unwrap();
        assert_eq!(
            m,
            EcosystemMatcher::scoped(RegistryFamily::Pypi, "requests")
        );
    }

    #[test]
    fn parse_scoped_npm_name_is_treated_as_bare() {
        let m: EcosystemMatcher = "@scope/pkg".parse().unwrap();
        assert_eq!(m, EcosystemMatcher::bare("@scope/pkg"));
    }

    #[test]
    fn parse_npm_prefix_with_scoped_name() {
        let m: EcosystemMatcher = "npm:@scope/pkg".parse().unwrap();
        assert_eq!(
            m,
            EcosystemMatcher::scoped(RegistryFamily::Npm, "@scope/pkg")
        );
    }

    #[test]
    fn parse_unknown_family_is_error() {
        let err = "pypy:lodash".parse::<EcosystemMatcher>().unwrap_err();
        assert!(matches!(
            err,
            EcosystemMatcherParseError::UnknownFamily { .. }
        ));
    }

    #[test]
    fn parse_empty_is_error() {
        let err = "".parse::<EcosystemMatcher>().unwrap_err();
        assert_eq!(err, EcosystemMatcherParseError::Empty);
    }

    #[test]
    fn bare_matcher_matches_any_family() {
        let m = EcosystemMatcher::bare("lodash");
        assert!(m.matches(RegistryFamily::Npm, "lodash"));
        assert!(m.matches(RegistryFamily::Pypi, "lodash"));
        assert!(!m.matches(RegistryFamily::Npm, "axios"));
    }

    #[test]
    fn scoped_matcher_only_matches_its_family() {
        let m = EcosystemMatcher::scoped(RegistryFamily::Npm, "lodash");
        assert!(m.matches(RegistryFamily::Npm, "lodash"));
        assert!(!m.matches(RegistryFamily::Pypi, "lodash"));
    }

    #[test]
    fn key_uses_registry_family_prefix() {
        let dep = ResolvedDependency {
            ecosystem: Ecosystem::Yarn,
            name: "lodash".into(),
            version: "1.0.0".into(),
            integrity: None,
            source: Source::Registry { url: "x".into() },
            direct: true,
            requested_by: vec![],
        };
        assert_eq!(dep.key(), "npm/lodash@1.0.0");
    }

    #[test]
    fn pypi_ecosystem_maps_to_pypi_family() {
        assert_eq!(Ecosystem::Pypi.registry_family(), RegistryFamily::Pypi);
    }

    #[test]
    fn pypi_dep_key_uses_pypi_prefix() {
        let dep = ResolvedDependency {
            ecosystem: Ecosystem::Pypi,
            name: "requests".into(),
            version: "2.31.0".into(),
            integrity: None,
            source: Source::Pypi {
                url: "https://files.pythonhosted.org/packages/abc/requests-2.31.0.tar.gz".into(),
            },
            direct: true,
            requested_by: vec![],
        };
        assert_eq!(dep.key(), "pypi/requests@2.31.0");
    }

    #[test]
    fn pypi_source_is_not_exotic() {
        let s = Source::Pypi {
            url: "https://files.pythonhosted.org/x".into(),
        };
        assert!(!s.is_exotic());
    }

    #[test]
    fn pypi_ecosystem_round_trips_through_serde() {
        let json = serde_json::to_string(&Ecosystem::Pypi).unwrap();
        assert_eq!(json, "\"pypi\"");
        let back: Ecosystem = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Ecosystem::Pypi);
    }

    #[test]
    fn pypi_source_round_trips_through_serde() {
        let s = Source::Pypi {
            url: "https://files.pythonhosted.org/packages/x/foo-1.0-py3-none-any.whl".into(),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Source = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}
