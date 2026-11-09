//! The start-up sequence every front end must run first (see the crate docs).
use std::sync::atomic::{AtomicBool, Ordering};

static DONE: AtomicBool = AtomicBool::new(false);

pub struct Startup {
    /// things that could not be hardened (show them to the user)
    pub warnings: Vec<String>,
    /// active swap devices, if any: the front end refuses to run unless the user passed `--allow-swap`
    pub swap: Option<Vec<String>>,
}

/// Run FIRST in `main`. In the file-cleaning helper process this never returns.
pub fn startup(args: &[String]) -> Startup {
    if crate::cleaner::is_worker_invocation(args) { crate::cleaner::worker_main(); }
    if !args.iter().any(|a| a == "--no-sandbox") { nerd_chat_strip::set_cleaner(crate::cleaner::sandboxed_clean); }
    let warnings = crate::hardening::harden();
    DONE.store(true, Ordering::SeqCst);
    Startup { warnings, swap: crate::hardening::swap_problem() }
}

/// `App::new` checks this: a front end that skipped `startup` would parse hostile files in-process and run without hardening.
pub fn is_done() -> bool { DONE.load(Ordering::SeqCst) }
