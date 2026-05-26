// raxis-supervisor::fd_limit — service-manager friendly NOFILE setup.
//
// Packaged service managers should be able to launch
// `raxis-supervisor start` directly. The supervisor raises its own
// soft `RLIMIT_NOFILE` before it starts the kernel, so launchd
// plists and other service definitions do not need shell-specific
// `ulimit` wrappers.

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NofileRaiseOutcome {
    AlreadySufficient {
        soft: u64,
        hard: u64,
        required: u64,
    },
    Raised {
        old_soft: u64,
        new_soft: u64,
        hard: u64,
        required: u64,
    },
    RaisedToHardBelowRequired {
        old_soft: u64,
        new_soft: u64,
        hard: u64,
        required: u64,
    },
    HardBelowRequired {
        soft: u64,
        hard: u64,
        required: u64,
    },
    Unsupported,
}

impl NofileRaiseOutcome {
    pub fn changed(self) -> bool {
        matches!(
            self,
            Self::Raised { .. } | Self::RaisedToHardBelowRequired { .. }
        )
    }

    pub fn still_below_required(self) -> bool {
        matches!(
            self,
            Self::RaisedToHardBelowRequired { .. } | Self::HardBelowRequired { .. }
        )
    }
}

#[cfg(unix)]
fn rlim_to_u64(value: libc::rlim_t) -> u64 {
    value as u64
}

#[cfg(unix)]
fn u64_to_rlim(value: u64) -> libc::rlim_t {
    value as libc::rlim_t
}

pub fn raise_nofile_soft_limit(required: u64) -> std::io::Result<NofileRaiseOutcome> {
    #[cfg(unix)]
    {
        use nix::sys::resource::{getrlimit, setrlimit, Resource};
        use std::io;

        let (soft, hard) = getrlimit(Resource::RLIMIT_NOFILE)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let soft_u64 = rlim_to_u64(soft);
        let hard_u64 = rlim_to_u64(hard);

        if soft_u64 >= required {
            return Ok(NofileRaiseOutcome::AlreadySufficient {
                soft: soft_u64,
                hard: hard_u64,
                required,
            });
        }

        let desired = required.min(hard_u64);
        if desired <= soft_u64 {
            return Ok(NofileRaiseOutcome::HardBelowRequired {
                soft: soft_u64,
                hard: hard_u64,
                required,
            });
        }

        setrlimit(Resource::RLIMIT_NOFILE, u64_to_rlim(desired), hard)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

        if desired < required {
            Ok(NofileRaiseOutcome::RaisedToHardBelowRequired {
                old_soft: soft_u64,
                new_soft: desired,
                hard: hard_u64,
                required,
            })
        } else {
            Ok(NofileRaiseOutcome::Raised {
                old_soft: soft_u64,
                new_soft: desired,
                hard: hard_u64,
                required,
            })
        }
    }

    #[cfg(not(unix))]
    {
        let _ = required;
        Ok(NofileRaiseOutcome::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raise_to_one_is_always_safe_on_real_hosts() {
        let outcome = raise_nofile_soft_limit(1).expect("read/raise nofile limit");
        assert!(!outcome.still_below_required());
    }
}
