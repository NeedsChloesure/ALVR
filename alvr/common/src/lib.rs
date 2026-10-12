mod average;
mod connection_result;
mod inputs;
mod logging;
mod primitives;
mod version;

use once_cell::sync::Lazy;
use parking_lot::{Condvar, Mutex, RwLockWriteGuard};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

pub use anyhow;
pub use glam;
pub use log;
pub use once_cell;
pub use parking_lot;
pub use semver;
pub use settings_schema;

pub use average::*;
pub use connection_result::*;
pub use inputs::*;
pub use log::{debug, error, info, warn};
pub use logging::*;
pub use primitives::*;
pub use version::*;

pub const ALVR_NAME: &str = "ALVR";

pub type OptLazy<T> = Lazy<Mutex<Option<T>>>;

pub const fn lazy_mut_none<T>() -> OptLazy<T> {
    Lazy::new(|| Mutex::new(None))
}

// Diagnostic helpers, used by the verbose logging in alvr_sockets and alvr_server_core. These are
// deliberately unconditional (they use `log` macros directly, not the `dbg_*` macros which are
// compiled out in release builds) so that a release build of the driver can be diagnosed.
pub fn hex_preview(bytes: &[u8]) -> String {
    const MAX_PREVIEW_BYTES: usize = 48;

    let mut preview = String::with_capacity(MAX_PREVIEW_BYTES * 2 + 3);
    for byte in bytes.iter().take(MAX_PREVIEW_BYTES) {
        preview.push_str(&format!("{byte:02x}"));
    }
    if bytes.len() > MAX_PREVIEW_BYTES {
        preview.push_str("...");
    }

    preview
}

pub fn io_err_desc(e: &std::io::Error) -> String {
    format!(
        "{e} (kind: {:?}, raw_os_error: {:?})",
        e.kind(),
        e.raw_os_error()
    )
}

// Simple wrapper for AtomicBool when using Ordering::Relaxed. Deref cannot be implemented (cannot
// return local reference)
#[derive(Default)]
pub struct RelaxedAtomic(AtomicBool);

impl RelaxedAtomic {
    pub const fn new(initial_value: bool) -> Self {
        Self(AtomicBool::new(initial_value))
    }

    pub fn value(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub fn set(&self, value: bool) {
        self.0.store(value, Ordering::Relaxed);
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum LifecycleState {
    StartingUp,
    Idle,
    Resumed,
    ShuttingDown,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Streaming,
    Disconnecting,
}

pub fn wait_rwlock<T>(condvar: &Condvar, guard: &mut RwLockWriteGuard<'_, T>) {
    let staging_mutex = Mutex::<()>::new(());
    let mut inner_guard = staging_mutex.lock();
    RwLockWriteGuard::unlocked(guard, move || {
        condvar.wait(&mut inner_guard);
    });
}
