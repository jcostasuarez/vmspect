//! Shared exclusion for VM discovery and inspection batches.

use crate::error::{Result, VmSpectError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

#[cfg(test)]
use std::sync::{Mutex, MutexGuard};

static ACTIVE_OPERATION: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Guard that marks the process-wide discovery/batch slot as available on drop.
pub(crate) struct ActiveOperationGuard(Arc<AtomicBool>);

impl Drop for ActiveOperationGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Acquires the process-wide discovery or inspection-batch slot.
pub(crate) fn acquire_active_operation() -> Result<ActiveOperationGuard> {
    let active = ACTIVE_OPERATION
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone();
    active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| {
            VmSpectError::Other(
                "another VM discovery or inspection batch is already running".to_string(),
            )
        })?;
    Ok(ActiveOperationGuard(active))
}

#[cfg(test)]
static TEST_OPERATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn lock_test_operation() -> MutexGuard<'static, ()> {
    TEST_OPERATION_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_operation_is_exclusive_and_released_by_drop() {
        let _test_lock = lock_test_operation();
        let guard = acquire_active_operation().expect("first operation acquires the slot");
        let error = acquire_active_operation()
            .err()
            .expect("second operation is rejected");
        assert!(error
            .to_string()
            .contains("another VM discovery or inspection batch is already running"));
        drop(guard);
        let _guard = acquire_active_operation().expect("drop releases the slot");
    }
}
