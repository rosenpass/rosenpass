use std::process::Command;
use thiserror::Error;

/// Errors that can occur when interacting with netctl
#[derive(Debug, Error)]
pub enum NetctlError {
    #[error("netctl command failed: {0}")]
    CommandFailed(String),

    #[error("netctl not found")]
    NotFound,

    #[error("netctl command not supported")]
    NotSupported,
}

/// Check if netctl is available on the system
pub fn is_netctl_available() -> bool {
    Command::new("netctl").arg("--help").output().is_ok()
}

/// Start a netctl service
pub fn start_service(service_name: &str) -> Result<(), NetctlError> {
    let output = Command::new("netctl")
        .arg("start")
        .arg(service_name)
        .output()
        .map_err(|_| NetctlError::NotFound)?;

    if !output.status.success() {
        return Err(NetctlError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(())
}

/// Stop a netctl service
pub fn stop_service(service_name: &str) -> Result<(), NetctlError> {
    let output = Command::new("netctl")
        .arg("stop")
        .arg(service_name)
        .output()
        .map_err(|_| NetctlError::NotFound)?;

    if !output.status.success() {
        return Err(NetctlError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(())
}

/// Check if a netctl service is active
pub fn is_service_active(service_name: &str) -> Result<bool, NetctlError> {
    let output = Command::new("netctl")
        .arg("status")
        .arg(service_name)
        .output()
        .map_err(|_| NetctlError::NotFound)?;

    if !output.status.success() {
        return Err(NetctlError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .to_lowercase()
        .contains("active"))
}