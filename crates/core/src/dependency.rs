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
}

impl Ecosystem {
    /// Returns the package-manager-neutral registry family. `npm`, `pnpm`,
    /// and `yarn` all consume the npm registry, so policy and signals can
    /// usually treat them uniformly.
    #[must_use]
    pub fn registry_family(self) -> RegistryFamily {
        match self {
            Self::Npm | Self::Pnpm | Self::Yarn => RegistryFamily::Npm,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryFamily {
    Npm,
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

/// Where the dependency was acquired from. Anything other than `Registry` is
/// considered "exotic" and can be blocked by policy.
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
}

impl Source {
    #[must_use]
    pub fn is_exotic(&self) -> bool {
        !matches!(self, Self::Registry { .. } | Self::Workspace)
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
            match self.ecosystem {
                Ecosystem::Npm | Ecosystem::Pnpm | Ecosystem::Yarn => "npm",
            },
            self.name,
            self.version
        )
    }
}
