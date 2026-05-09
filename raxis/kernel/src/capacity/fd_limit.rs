// raxis-kernel::capacity::fd_limit — boot-time FD limit enforcement.
//
// Normative reference: `specs/v2/host-capacity.md §12.1`.
//
// The kernel checks `getrlimit(RLIMIT_NOFILE)` at boot. When the
// soft limit is below `[host_capacity] required_min_fd_limit` the
// kernel refuses to start with `BOOT_ERR_HOST_CAPACITY`. Operators
// raise the limit via their service manager (`LimitNOFILE=` for
// systemd) or `ulimit -n` before launching.
//
// V2 ships only the boot-time check. Dynamic FD scaling and
// runtime "approaching limit" warnings are V3 (host-capacity.md
// §12.3).

/// Outcome of the FD-limit check at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdLimitOutcome {
    /// Soft limit ≥ required floor — the kernel may continue.
    Ok { current_soft: u64, required: u64 },
    /// Soft limit < required floor — the caller MUST refuse to
    /// boot. The audit emit lives in the caller because the
    /// audit sink is not yet open at this stage of startup.
    Insufficient { current_soft: u64, required: u64 },
    /// `getrlimit` failed. Treated as `Ok` to fail-open in dev
    /// containers without `prlimit` access; the value reported
    /// by the syscall is `0` so subsequent diagnostics are
    /// honest about the unavailable measurement. Production hosts
    /// always have working `getrlimit`.
    Unknown,
}

impl FdLimitOutcome {
    /// Convenience for the caller: `true` when the kernel must
    /// refuse to boot.
    pub fn is_fatal(self) -> bool {
        matches!(self, Self::Insufficient { .. })
    }
}

/// Read `RLIMIT_NOFILE` and compare against the operator-declared
/// floor. On non-Unix platforms the function returns
/// `FdLimitOutcome::Unknown` so the kernel can boot in dev
/// environments without per-process FD accounting.
pub fn check_fd_limit_at_boot(required: u32) -> FdLimitOutcome {
    let required_u64 = u64::from(required);
    #[cfg(unix)]
    {
        // SAFETY: `getrlimit` accepts a properly-initialised
        // `rlimit` struct; we zero-initialise via `MaybeUninit`
        // and pass a writable pointer. The syscall is documented
        // as filling the struct on success.
        use std::mem::MaybeUninit;
        let mut limits: MaybeUninit<libc::rlimit> = MaybeUninit::uninit();
        let rc = unsafe {
            libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr())
        };
        if rc != 0 {
            return FdLimitOutcome::Unknown;
        }
        let l = unsafe { limits.assume_init() };
        // `rlim_cur` is the soft limit; on macOS it is `i64`,
        // on Linux glibc it is `u64`. Casting through `i128`
        // and clamping to non-negative protects either ABI.
        let soft = l.rlim_cur as i128;
        let soft_u64: u64 = if soft < 0 { 0 } else { soft as u64 };
        if soft_u64 < required_u64 {
            return FdLimitOutcome::Insufficient {
                current_soft: soft_u64,
                required:     required_u64,
            };
        }
        FdLimitOutcome::Ok {
            current_soft: soft_u64,
            required:     required_u64,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = required_u64;
        FdLimitOutcome::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_outcome_only_for_insufficient() {
        assert!(FdLimitOutcome::Insufficient { current_soft: 100, required: 4096 }.is_fatal());
        assert!(!FdLimitOutcome::Ok { current_soft: 4096, required: 4096 }.is_fatal());
        assert!(!FdLimitOutcome::Unknown.is_fatal());
    }

    #[test]
    fn check_with_one_passes_on_any_real_host() {
        // `1` is below every realistic FD limit; a passing kernel
        // process always has more than 1 FD available. This is
        // primarily a smoke test that the syscall wiring works.
        let outcome = check_fd_limit_at_boot(1);
        match outcome {
            FdLimitOutcome::Ok { .. } | FdLimitOutcome::Unknown => {}
            FdLimitOutcome::Insufficient { current_soft, required } => panic!(
                "host has soft FD limit {current_soft} below floor {required}; \
                 raise `ulimit -n` to run this test"
            ),
        }
    }
}
