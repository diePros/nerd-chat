//! Process hardening and the swap check, shared by every front end (the terminal and the GUI refuse to run the same way).
/// Process hardening that needs no `unsafe`: no core dumps (a dump of the unlocked heap would put
/// keys on disk), and not ptrace/proc-mem readable by same-user processes.
/// Returns human-readable warnings for anything that could not be applied.
pub fn harden() -> Vec<String> {
    use rustix::process::{setrlimit, Resource, Rlimit};
    let mut w = Vec::new();
    if setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).is_err() {
        w.push("could not disable core dumps".to_string());
    }
    #[cfg(target_os = "linux")]
    if rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).is_err() {
        w.push("could not mark the process non-dumpable".to_string());
    }
    w
}

/// Active swap devices/files from `/proc/swaps` text (everything after the header line).
pub fn parse_swaps(text: &str) -> Vec<String> {
    text.lines().skip(1).filter_map(|l| l.split_whitespace().next()).map(str::to_string).collect()
}

/// Refuse to run with swap active: the kernel may write our memory (keys, plaintext) to disk, where it survives power-off.
/// (Without swap there is also no hibernation image.) `None` = unknown (can't read /proc/swaps): treated as OK.
pub fn swap_problem() -> Option<Vec<String>> {
    let active = parse_swaps(&std::fs::read_to_string("/proc/swaps").ok()?);
    if active.is_empty() { None } else { Some(active) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swaps_are_parsed_from_proc_text() {
        let none = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
        assert!(parse_swaps(none).is_empty());
        let some = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/swapfile                               file\t\t524284\t\t524280\t\t-1\n/dev/zram0                              partition\t1024\t0\t100\n";
        assert_eq!(parse_swaps(some), vec!["/swapfile", "/dev/zram0"]);
        assert!(parse_swaps("").is_empty());
    }
}
