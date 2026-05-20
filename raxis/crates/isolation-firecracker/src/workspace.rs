//! Firecracker workspace transport.
//!
//! Firecracker intentionally exposes a narrow device model: virtio-blk,
//! virtio-net, virtio-vsock, balloon, serial, and the minimal keyboard
//! controller. It does not expose the AVF-style VirtioFS device RAXIS
//! uses on macOS. To keep the Linux substrate honest and usable, this
//! module maps each [`raxis_isolation::WorkspaceMount`] to a per-session
//! ext4 image attached as a virtio-blk drive, then synchronizes
//! read-write images back into the kernel-owned host worktree before
//! intent admission and once more at shutdown.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use raxis_isolation::{MountMode, WorkspaceMount};

use crate::api::{ApiError, Drive};

const MIN_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const RW_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;
const RO_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMAGE_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Prepared Firecracker mount transport for one session.
#[derive(Debug, Clone)]
pub(crate) struct PreparedWorkspaceMounts {
    /// Firecracker `/drives/{id}` bodies for workspace images.
    pub drives: Vec<Drive>,
    /// Guest env payload consumed by planner-core guest init.
    pub block_mounts_env: Option<String>,
    sync_plan: WorkspaceSyncPlan,
}

impl PreparedWorkspaceMounts {
    /// Empty transport for sessions with no workspace mounts.
    pub fn empty() -> Self {
        Self {
            drives: Vec::new(),
            block_mounts_env: None,
            sync_plan: WorkspaceSyncPlan::empty(),
        }
    }

    /// Copyback plan retained by the live session handle.
    pub fn sync_plan(&self) -> WorkspaceSyncPlan {
        self.sync_plan.clone()
    }
}

/// Copyback/cleanup plan retained by the live session.
#[derive(Debug, Clone)]
pub(crate) struct WorkspaceSyncPlan {
    entries: Vec<WorkspaceImage>,
}

impl WorkspaceSyncPlan {
    /// Empty sync plan for mount-less sessions.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Whether any mount needs host copyback before intent admission.
    pub fn has_readwrite(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| matches!(entry.mode, MountMode::ReadWrite))
    }

    /// Copy read-write image contents back into their host worktree.
    pub fn sync_readwrite(&self, final_pass: bool) -> Result<(), String> {
        for entry in &self.entries {
            if matches!(entry.mode, MountMode::ReadWrite) {
                entry.sync_back(final_pass)?;
            }
        }
        Ok(())
    }

    /// Remove transient image/extract files after successful teardown.
    pub fn cleanup_images(&self) {
        for entry in &self.entries {
            let _ = fs::remove_file(&entry.image_path);
            let _ = fs::remove_dir_all(entry.extract_dir());
        }
    }
}

#[derive(Debug, Clone)]
struct WorkspaceImage {
    image_path: PathBuf,
    host_path: PathBuf,
    guest_path: String,
    mode: MountMode,
}

impl WorkspaceImage {
    fn extract_dir(&self) -> PathBuf {
        let file_name = self
            .image_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("workspace.img");
        self.image_path
            .with_file_name(format!("{file_name}.extract"))
    }

    fn sync_back(&self, final_pass: bool) -> Result<(), String> {
        if final_pass {
            run_e2fsck(&self.image_path)?;
        }
        let extract_dir = self.extract_dir();
        if extract_dir.exists() {
            fs::remove_dir_all(&extract_dir)
                .map_err(|e| format!("remove stale extract dir {}: {e}", extract_dir.display()))?;
        }
        fs::create_dir_all(&extract_dir)
            .map_err(|e| format!("create extract dir {}: {e}", extract_dir.display()))?;
        set_private_dir_permissions(&extract_dir)
            .map_err(|e| format!("chmod extract dir {}: {e}", extract_dir.display()))?;

        let command = format!("rdump / {}", extract_dir.display());
        let output = Command::new("debugfs")
            .arg("-R")
            .arg(command)
            .arg(&self.image_path)
            .output()
            .map_err(|e| format!("exec debugfs: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "debugfs rdump {} for {} failed: status={} stderr={}",
                self.image_path.display(),
                self.guest_path,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim(),
            ));
        }

        sync_tree_contents(&extract_dir, &self.host_path).map_err(|e| {
            format!(
                "copy back {} into {}: {e}",
                self.guest_path,
                self.host_path.display()
            )
        })?;
        Ok(())
    }
}

/// Prepare all workspace mounts as ext4 virtio-blk drives.
pub(crate) fn prepare(
    mounts: &[WorkspaceMount],
    runtime_dir: &Path,
    session_name: &str,
    root_drive_present: bool,
) -> Result<PreparedWorkspaceMounts, ApiError> {
    if mounts.is_empty() {
        return Ok(PreparedWorkspaceMounts::empty());
    }

    ensure_tool("mkfs.ext4")?;
    if mounts
        .iter()
        .any(|mount| matches!(mount.mode, MountMode::ReadWrite))
    {
        ensure_tool("debugfs")?;
        ensure_tool("e2fsck")?;
    }

    let first_device_index = if root_drive_present { 1 } else { 0 };
    let mut drives = Vec::with_capacity(mounts.len());
    let mut env_entries = Vec::with_capacity(mounts.len());
    let mut sync_entries = Vec::with_capacity(mounts.len());

    for (idx, mount) in mounts.iter().enumerate() {
        validate_mount(mount)?;
        let drive_id = format!("mount{idx}");
        let image_path = runtime_dir.join(format!("{session_name}.{drive_id}.ext4"));
        let size = planned_image_size(&mount.host_path, mount.mode)?;
        create_ext4_image(&mount.host_path, &image_path, size)?;

        let device_path = virtio_blk_device_path(first_device_index + idx).ok_or_else(|| {
            ApiError::MalformedResponse(format!(
                "too many Firecracker workspace mounts: index {} has no /dev/vdX mapping",
                first_device_index + idx
            ))
        })?;
        let mode = match mount.mode {
            MountMode::ReadOnly => "ro",
            MountMode::ReadWrite => "rw",
        };
        env_entries.push(format!(
            "{device}:{}:{mode}:ext4",
            mount.guest_path,
            device = device_path,
        ));
        drives.push(Drive {
            drive_id,
            path_on_host: image_path.clone(),
            is_root_device: false,
            is_read_only: matches!(mount.mode, MountMode::ReadOnly),
        });
        sync_entries.push(WorkspaceImage {
            image_path,
            host_path: mount.host_path.clone(),
            guest_path: mount.guest_path.clone(),
            mode: mount.mode,
        });
    }

    Ok(PreparedWorkspaceMounts {
        drives,
        block_mounts_env: Some(env_entries.join(",")),
        sync_plan: WorkspaceSyncPlan {
            entries: sync_entries,
        },
    })
}

fn validate_mount(mount: &WorkspaceMount) -> Result<(), ApiError> {
    if mount.guest_path.is_empty() || !mount.guest_path.starts_with('/') {
        return Err(ApiError::MalformedResponse(format!(
            "workspace mount guest_path must be absolute, got {:?}",
            mount.guest_path
        )));
    }
    if mount.guest_path.contains([',', ':', '\n', '\r']) {
        return Err(ApiError::MalformedResponse(format!(
            "workspace mount guest_path {:?} contains a delimiter reserved by RAXIS_BLOCK_MOUNTS",
            mount.guest_path
        )));
    }
    let md = fs::metadata(&mount.host_path).map_err(|e| {
        ApiError::MalformedResponse(format!(
            "workspace mount host_path {} not readable: {e}",
            mount.host_path.display()
        ))
    })?;
    if !md.is_dir() {
        return Err(ApiError::MalformedResponse(format!(
            "workspace mount host_path {} is not a directory",
            mount.host_path.display()
        )));
    }
    Ok(())
}

fn ensure_tool(tool: &str) -> Result<(), ApiError> {
    let status = Command::new(tool).arg("-V").status().map_err(|e| {
        ApiError::MalformedResponse(format!(
            "Firecracker workspace transport requires `{tool}` from e2fsprogs: {e}"
        ))
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(ApiError::MalformedResponse(format!(
            "Firecracker workspace transport requires `{tool}` from e2fsprogs; version probe exited with {status}"
        )))
    }
}

fn planned_image_size(host_path: &Path, mode: MountMode) -> Result<u64, ApiError> {
    let used = dir_size(host_path).map_err(|e| {
        ApiError::MalformedResponse(format!(
            "compute workspace size {}: {e}",
            host_path.display()
        ))
    })?;
    let headroom = match mode {
        MountMode::ReadOnly => RO_HEADROOM_BYTES,
        MountMode::ReadWrite => std::cmp::max(used / 2, RW_HEADROOM_BYTES),
    };
    let requested = used.saturating_add(headroom);
    let clamped = requested.clamp(MIN_IMAGE_BYTES, MAX_IMAGE_BYTES);
    Ok(round_up_mib(clamped))
}

fn round_up_mib(bytes: u64) -> u64 {
    const MIB: u64 = 1024 * 1024;
    bytes.saturating_add(MIB - 1) / MIB * MIB
}

fn dir_size(path: &Path) -> io::Result<u64> {
    let md = fs::symlink_metadata(path)?;
    if md.is_file() {
        return Ok(round_up_4k(md.len()));
    }
    if md.file_type().is_symlink() {
        return Ok(4096);
    }
    let mut total = 4096;
    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            total += dir_size(&entry?.path())?;
        }
    }
    Ok(total)
}

fn round_up_4k(bytes: u64) -> u64 {
    const PAGE: u64 = 4096;
    bytes.saturating_add(PAGE - 1) / PAGE * PAGE
}

fn create_ext4_image(source_dir: &Path, image_path: &Path, size: u64) -> Result<(), ApiError> {
    if let Some(parent) = image_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            ApiError::MalformedResponse(format!("create {}: {e}", parent.display()))
        })?;
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(image_path)
        .map_err(|e| {
            ApiError::MalformedResponse(format!("create image {}: {e}", image_path.display()))
        })?;
    file.set_len(size).map_err(|e| {
        ApiError::MalformedResponse(format!("size image {}: {e}", image_path.display()))
    })?;
    set_private_file_permissions(image_path).map_err(|e| {
        ApiError::MalformedResponse(format!("chmod image {}: {e}", image_path.display()))
    })?;
    drop(file);

    let output = Command::new("mkfs.ext4")
        .arg("-q")
        .arg("-F")
        .arg("-d")
        .arg(source_dir)
        .arg(image_path)
        .output()
        .map_err(|e| ApiError::MalformedResponse(format!("exec mkfs.ext4: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let _ = fs::remove_file(image_path);
        Err(ApiError::MalformedResponse(format!(
            "mkfs.ext4 -d {} {} failed: status={} stderr={}",
            source_dir.display(),
            image_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        )))
    }
}

fn run_e2fsck(image_path: &Path) -> Result<(), String> {
    let output = Command::new("e2fsck")
        .arg("-fy")
        .arg(image_path)
        .output()
        .map_err(|e| format!("exec e2fsck: {e}"))?;
    let code = output.status.code().unwrap_or(8);
    // e2fsck uses bit flags. 0 means clean; 1 means fixed; 2 means
    // fixed and reboot would be needed for a live system. This is an
    // offline image, so accept any result without the uncorrected bit.
    if code & 4 == 0 {
        Ok(())
    } else {
        Err(format!(
            "e2fsck {} failed: status={} stderr={}",
            image_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        ))
    }
}

fn virtio_blk_device_path(index: usize) -> Option<String> {
    if index >= 26 {
        return None;
    }
    let letter = (b'a' + u8::try_from(index).ok()?) as char;
    Some(format!("/dev/vd{letter}"))
}

fn sync_tree_contents(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;

    let mut desired = BTreeSet::new();
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == OsStr::new("lost+found") {
            continue;
        }
        desired.insert(name.clone());
        copy_entry(&entry.path(), &dst.join(name))?;
    }

    for entry in fs::read_dir(dst)? {
        let entry = entry?;
        if !desired.contains(&entry.file_name()) {
            remove_path(&entry.path())?;
        }
    }
    Ok(())
}

fn copy_entry(src: &Path, dst: &Path) -> io::Result<()> {
    let md = fs::symlink_metadata(src)?;
    if md.file_type().is_symlink() {
        remove_path_if_exists(dst)?;
        #[cfg(unix)]
        {
            let target = fs::read_link(src)?;
            symlink(target, dst)?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "symlink copyback is unsupported on this host",
            ));
        }
    }
    if md.is_dir() {
        if fs::symlink_metadata(dst)
            .map(|m| !m.is_dir())
            .unwrap_or(false)
        {
            remove_path(dst)?;
        }
        fs::create_dir_all(dst)?;
        sync_tree_contents(src, dst)?;
        copy_permissions(&md, dst)?;
        return Ok(());
    }
    if md.is_file() {
        if fs::symlink_metadata(dst)
            .map(|m| !m.is_file())
            .unwrap_or(false)
        {
            remove_path(dst)?;
        }
        fs::copy(src, dst)?;
        copy_permissions(&md, dst)?;
    }
    Ok(())
}

fn copy_permissions(md: &fs::Metadata, dst: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mode = md.permissions().mode();
        fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (md, dst);
    }
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn set_private_dir_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        remove_path(path)?;
    }
    Ok(())
}

fn remove_path(path: &Path) -> io::Result<()> {
    let md = fs::symlink_metadata(path)?;
    if md.is_dir() && !md.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_isolation::ContentHash;

    fn fixture_mount(guest_path: &str, mode: MountMode) -> WorkspaceMount {
        WorkspaceMount {
            host_path: PathBuf::from("/tmp/raxis-fixture-workspace"),
            guest_path: guest_path.to_owned(),
            mode,
            content_hash: Some(ContentHash([0u8; 32])),
        }
    }

    #[test]
    fn virtio_blk_device_paths_are_stable() {
        assert_eq!(virtio_blk_device_path(0).as_deref(), Some("/dev/vda"));
        assert_eq!(virtio_blk_device_path(1).as_deref(), Some("/dev/vdb"));
        assert_eq!(virtio_blk_device_path(25).as_deref(), Some("/dev/vdz"));
        assert_eq!(virtio_blk_device_path(26), None);
    }

    #[test]
    fn validate_mount_rejects_relative_guest_path() {
        let mount = fixture_mount("workspace", MountMode::ReadOnly);
        let err = validate_mount(&mount).unwrap_err();
        match err {
            ApiError::MalformedResponse(reason) => {
                assert!(reason.contains("guest_path must be absolute"));
            }
            other => panic!("expected malformed response, got {other:?}"),
        }
    }

    #[test]
    fn validate_mount_rejects_block_mount_env_delimiters() {
        let mount = fixture_mount("/workspace:evil", MountMode::ReadOnly);
        let err = validate_mount(&mount).unwrap_err();
        match err {
            ApiError::MalformedResponse(reason) => {
                assert!(reason.contains("reserved by RAXIS_BLOCK_MOUNTS"));
            }
            other => panic!("expected malformed response, got {other:?}"),
        }
    }

    #[test]
    fn image_size_has_headroom_and_bounds() {
        assert_eq!(round_up_mib(1), 1024 * 1024);
        assert_eq!(round_up_4k(1), 4096);
        let min = planned_size_for_test(0, MountMode::ReadOnly);
        assert_eq!(min, MIN_IMAGE_BYTES);
        let rw = planned_size_for_test(512 * 1024 * 1024, MountMode::ReadWrite);
        assert!(rw > 512 * 1024 * 1024);
    }

    fn planned_size_for_test(used: u64, mode: MountMode) -> u64 {
        let headroom = match mode {
            MountMode::ReadOnly => RO_HEADROOM_BYTES,
            MountMode::ReadWrite => std::cmp::max(used / 2, RW_HEADROOM_BYTES),
        };
        round_up_mib(
            used.saturating_add(headroom)
                .clamp(MIN_IMAGE_BYTES, MAX_IMAGE_BYTES),
        )
    }
}
