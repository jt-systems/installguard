//! The `LockfileAdapter` trait. Adapters live in `crates/adapters/<eco>/`.

use std::path::Path;

use crate::dependency::{Ecosystem, ResolvedDependency};

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
    #[error("unsupported lockfile version: {0}")]
    UnsupportedVersion(String),
}

pub trait LockfileAdapter: Send + Sync {
    /// Stable adapter identifier (e.g. `"npm"`, `"pnpm"`).
    fn id(&self) -> &'static str;

    /// Ecosystem the adapter produces.
    fn ecosystem(&self) -> Ecosystem;

    /// True if this adapter recognises the file at `path` by name.
    fn detects(&self, path: &Path) -> bool;

    /// Parse the lockfile at `path` into normalised dependencies.
    fn parse(&self, path: &Path) -> Result<Vec<ResolvedDependency>, AdapterError>;
}
