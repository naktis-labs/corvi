//! Panic containment at the collector boundary.
//!
//! `catch_unwind` stops the unwind, but not the panic hook: by the time the
//! unwind is caught, the hook has already written the payload — which a
//! third-party collector may have filled with a private value — to the log
//! stream. Suppression prevents that leak only while this crate's hook remains
//! installed; hosts must not replace it after telemetry starts if they rely on
//! this protection.
//!
//! The hook is therefore replaced once, at the first flush, with a hook that
//! swallows panics raised on a collector thread and delegates every other
//! panic to the hook that was installed before telemetry. Suppression is
//! scoped by a thread-local flag that only the collector's worker thread
//! holds, so the installed wrapper delegates panics on other threads to the
//! previous hook.
//!
//! # Caveats
//!
//! * The hook is process-global. If the host replaces the panic hook after
//!   telemetry's first flush, *that* hook fires on a collector thread and
//!   will see the payload; a host that installs its own hook should do so
//!   before enabling telemetry. Concurrent host hook changes during installation
//!   are also not coordinated. Between taking the old hook and installing the
//!   wrapper, unrelated panics use Rust's default hook rather than the host hook.
//! * An externally installed hook is never restored or removed by this
//!   module; telemetry only ever wraps the hook that was current at its first
//!   flush and delegates to it.
//! * If the current thread's state is unreachable while a panic is in
//!   flight, the hook defaults to *not* suppressing: an unexpected panic is
//!   reported rather than hidden.

use std::cell::Cell;
use std::panic::{self, PanicHookInfo};
use std::sync::Once;

thread_local! {
    /// Held by a thread while it runs a collector call, so a panic raised by
    /// the collector itself is swallowed instead of written to the log.
    static SUPPRESSED: Cell<bool> = const { Cell::new(false) };
}

/// Serializes installation without storing the hook outside its wrapper.
static INSTALL: Once = Once::new();

/// Run `call`, swallowing panic output raised on this thread while it runs.
///
/// `call` is expected to contain the `catch_unwind` around a collector call
/// and not to unwind; a `Drop` guard resets the flag even if it does.
pub fn with_suppressed_output<R>(call: impl FnOnce() -> R) -> R {
    ensure_hook_installed();
    SUPPRESSED.with(|flag| flag.set(true));
    let _guard = ResetOnDrop;
    call()
}

struct ResetOnDrop;

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        SUPPRESSED.with(|flag| flag.set(false));
    }
}

fn ensure_hook_installed() {
    INSTALL.call_once(|| {
        let delegate = panic::take_hook();
        panic::set_hook(Box::new(move |info| suppressing_hook(info, &*delegate)));
    });
}

fn suppressing_hook(
    info: &PanicHookInfo<'_>,
    delegate: &(dyn Fn(&PanicHookInfo<'_>) + Send + Sync),
) {
    let suppressed = SUPPRESSED.try_with(|flag| flag.get()).unwrap_or(false);
    if suppressed {
        // The payload is deliberately not formatted, not stringified and not
        // passed anywhere: it may carry a private value.
        return;
    }
    delegate(info);
}
