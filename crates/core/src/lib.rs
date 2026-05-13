//! InstallGuard core: ecosystem-agnostic types, the lockfile-adapter and
//! signal-provider traits, and the built-in policy engine.
//!
//! This crate has no I/O. All network and filesystem work lives in adapter
//! and signal crates so the core can be unit-tested deterministically.

#![doc(html_root_url = "https://docs.rs/installguard-core/0.0.0")]

pub mod adapter;
pub mod attestation;
pub mod audit;
pub mod decision;
pub mod dependency;
pub mod lockfile;
pub mod policy;
pub mod sbom;
pub mod signal;
pub mod vex;

pub use adapter::LockfileAdapter;
pub use attestation::{Statement, PREDICATE_TYPE, STATEMENT_TYPE};
pub use decision::{Decision, Reason};
pub use dependency::{Ecosystem, Integrity, ResolvedDependency, Source};
pub use lockfile::{InstallguardLock, LockDecision, LockEntry, LockError, LockMismatch};
pub use policy::{Policy, PolicyError, ScriptPolicy};
pub use signal::{Signal, SignalProvider, SignalSet};
