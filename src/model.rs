//! Basic control, result and error handling implementation.
use std::net::IpAddr;
use std::process::ExitCode;

use pnet::util::MacAddr;

use crate::format::format_exit;

/// Exit codes for the Scanner, following linux sysexits.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ScannerExitCode {
    Ok = 0,
    Cli = 64,
    Internal = 70,
    Os = 71,
    Io = 74,
    TempFail = 75,
    Protocol = 76,
    Perms = 77,
    Config = 78,
    Timeout = 124,
    Interrupt = 130,
}

impl ScannerExitCode {
    /// Returns a code 'meaning' string.
    pub fn meaning(&self) -> &str {
        match self {
            ScannerExitCode::Ok => "OK",
            ScannerExitCode::Cli => "Command line interface error",
            ScannerExitCode::Internal => "Internal error",
            ScannerExitCode::Os => "Operating system error",
            ScannerExitCode::Io => "I/O error",
            ScannerExitCode::TempFail => "Temporary failure",
            ScannerExitCode::Protocol => "Protocol error",
            ScannerExitCode::Perms => "Permission denied",
            ScannerExitCode::Config => "Configuration error",
            ScannerExitCode::Timeout => "Timeout",
            ScannerExitCode::Interrupt => "Interrupted",
        }
    }
}

/// Scanner error containing custom exit code and formatted message.
#[derive(Debug, Clone)]
pub struct ScannerError {
    /// The exit code to return.
    pub code: ScannerExitCode,
    /// Friendly error message.
    pub message: String,
}

/// Runtime control messages sent from side threads (e.g. signal listener) to the scanner.
#[derive(Debug, Clone, Copy)]
pub enum ControlMessage {
    /// Request a graceful shutdown with a matching exit code.
    Shutdown(ScannerExitCode),
}

impl From<ScannerError> for ExitCode {
    fn from(value: ScannerError) -> Self {
        if value.code != ScannerExitCode::Ok {
            eprintln!("{}", format_exit(value.code, value.message));
        }
        ExitCode::from(value.code as u8)
    }
}

/// IP address and MAC address pair for discovered hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressPair {
    pub ip: IpAddr,
    pub mac: MacAddr,
}

/// IP address match pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScanMatch {
    pub mac_addr: Option<MacAddr>,
    pub icmp_responded: bool,
}

impl Default for ScanMatch {
    fn default() -> Self {
        Self {
            mac_addr: None,
            icmp_responded: false,
        }
    }
}
