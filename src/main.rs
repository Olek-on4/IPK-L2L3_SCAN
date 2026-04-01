//! L2L3-scanner: Scans for available IPv4 and IPv6 addresses on a specified network interface.

use std::{net::IpAddr, process::ExitCode};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use clap::Parser;
use pnet::datalink::NetworkInterface;
use ipnetwork::IpNetwork;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

/// Exit codes for the scanner, following BSD sysexits and some custom codes.
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
    /// Returns a code 'meaning' string
    fn meaning(&self) -> &str {
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

/// Scanner error containing custom exit code and formatted message
pub struct ScannerError {
    /// The exit code to return
    code: ScannerExitCode,
    /// Friendly error message
    message: String,
}

/// Runtime control messages sent from side threads (e.g. signal listener) to the scanner.
#[derive(Debug, Clone, Copy)]
enum ControlMessage {
    /// Request a graceful shutdown with a matching exit code.
    Shutdown(ScannerExitCode),
}

impl From<ScannerError> for ExitCode {
    fn from(value: ScannerError) -> Self {
        if value.code != ScannerExitCode::Ok {
            eprintln!("{}: {}", value.code.meaning(), value.message);
        }
        ExitCode::from(value.code as u8)
    }
}

/// Command Line Interface arguments for the Scanner
#[derive(Debug, clap::Parser)]
#[command(name = "l2l3-scanner")]
#[command(about = "Scans for available IpV4 and IpV6 addresses on provided interface", long_about = None)]
struct Cli {
    /// Available network interface to scan (e.g. 'wlan0'), or list interfaces if not provided
    #[arg(short, value_name = "INTERFACE", num_args = 0..=1)]
    interface: Option<Option<String>>,

    /// List of subnet values defining scanning ranges (e.g. '192.168.1.0/24')
    #[arg(short, value_name = "SUBNET")]
    subnets: Option<Vec<IpNetwork>>,

    /// Program timeout value in milliseconds
    #[arg(short, default_value_t = 1000)]
    timeout: u64,
}

/// Main scanner struct, holds configuration for a scan operation.
#[derive(Debug)]
struct Scanner {
    /// The network interface to scan
    interface: NetworkInterface,
    /// List of subnets to scan
    networks: Vec<IpNetwork>,
    /// Timeout for the scan
    timeout: Duration,
    /// Read handle of signal handling thread
    control_rx: Receiver<ControlMessage>,
}

impl Scanner {
    /// Build scanner from CLI + control channel.
    fn try_new(value: Cli, control_rx: Receiver<ControlMessage>) -> Result<Self, ScannerError> {
        // No arguments, help not asked, exit with error
        if value.interface.is_none() && value.subnets.is_none() {
            return Err(ScannerError {
                code: ScannerExitCode::Cli,
                message: "No arguments provided".to_string(),
            });
        }

        // Used in several arms
        let interfaces = pnet::datalink::interfaces();
        match value.interface {
            // -i provided
            Some(iface) => match iface {
                // -i <iface>
                Some(iface) => {
                    let interface = interfaces
                        .into_iter()
                        .find(|inter| inter.name == iface)
                        .ok_or_else(|| ScannerError {
                            code: ScannerExitCode::Cli,
                            message: format!("Interface '{}' not found", iface),
                        })?;

                    match value.subnets {
                        // -s present, scanner config is complete
                        Some(subnets) => Ok(Self {
                            interface,
                            networks: subnets,
                            timeout: Duration::from_millis(value.timeout),
                            control_rx,
                        }),
                        // -s missing while interface was requested
                        None => Err(ScannerError {
                            code: ScannerExitCode::Cli,
                            message: "No subnets specified".to_string(),
                        }),
                    }
                }
                // -i used without value: list interfaces and exit successfully
                None => {
                    println!("Available interfaces:");
                    for iface in interfaces {
                        println!("{}", iface.name);
                    }

                    Err(ScannerError {
                        code: ScannerExitCode::Ok,
                        message: "Interface list generated".to_string(),
                    })
                }
            },
            // no -i: treat as CLI usage error
            None => Err(ScannerError {
                code: ScannerExitCode::Cli,
                message: "-i option was not used".to_string(),
            }),
        }
    }

    /// Quick shutdown check between batches.
    fn check_shutdown(&self) -> Result<(), ScannerError> {
        match self.control_rx.try_recv() {
            // signal thread requested stop
            Ok(ControlMessage::Shutdown(code)) => Err(ScannerError {
                code,
                message: "Graceful shutdown requested by signal".to_string(),
            }),
            Err(err) => match err {
                // normal path: no shutdown request right now
                mpsc::TryRecvError::Empty => Ok(()),
                // control channel closed unexpectedly
                mpsc::TryRecvError::Disconnected => Err(ScannerError {
                    code: ScannerExitCode::Internal,
                    message: format!("Control channel error: {err:?}"),
                }),
            },
        }
    }

    fn scan_address(&self, _addr: &IpAddr) -> Result<bool, ScannerError> {
        // TODO: NDP/ARP probe
        Ok(true)
    }

    /// Scan one subnet batch, skip first/last IP.
    fn scan_batch(&self, network: &IpNetwork) -> Result<Vec<IpAddr>, ScannerError> {
        let mut addr_iter = network.iter();
        let mut discovered = Vec::new();

        // Skip first IP.
        addr_iter.next();

        // One-step lookahead so last IP is skipped.
        let Some(mut prev) = addr_iter.next() else {
            return Ok(discovered);
        };

        for current in addr_iter {
            discovered.push(prev);
            prev = current;
        }

        Ok(discovered)
    }

    /// Runs the scan operation. Returns a vector of discovered IP addresses or a ScannerError.
    fn run(&self) -> Result<Vec<IpAddr>, ScannerError> {
        // Start timing the scan
        let time_start = Instant::now();
        let deadline = time_start + self.timeout;
        let mut discovered = Vec::new();

        for network in &self.networks {
            if Instant::now() >= deadline {
                return Err(ScannerError {
                    code: ScannerExitCode::Timeout,
                    message: "Scanning timed out".to_string(),
                });
            }

            // Check for signal before starting the next batch.
            self.check_shutdown()?;

            let batch = self.scan_batch(network)?;
            discovered.extend(batch);
        }

        Ok(discovered)
    }
}

/// Spawns a background thread that waits for SIGINT/SIGTERM and forwards shutdown to scanner.
fn spawn_listener(control_tx: Sender<ControlMessage>) -> Result<(), ScannerError> {
    let mut signals = Signals::new([SIGINT, SIGTERM]).map_err(|err| ScannerError {
        code: ScannerExitCode::Os,
        message: format!("Failed to register signal handlers: {err}"),
    })?;

    thread::Builder::new()
        .name("signal-listener".to_string())
        .spawn(move || {
            for signal in signals.forever() {
                let code = match signal {
                    // Ctrl+C
                    SIGINT => ScannerExitCode::Interrupt,
                    // kill -TERM
                    SIGTERM => ScannerExitCode::TempFail,
                    // fallback for any unexpected signal value
                    _ => ScannerExitCode::Internal,
                };

                // Scanner may have already finished
                let _ = control_tx.send(ControlMessage::Shutdown(code));
                break;
            }
        })
        .map_err(|err| ScannerError {
            code: ScannerExitCode::Internal,
            message: format!("Failed to spawn signal listener thread: {err}"),
        })?;

    Ok(())
}

/// Entry point for the scanner application.
/// Parses CLI arguments, constructs the scanner, and runs the scan or lists interfaces.
fn main() -> ExitCode {
    let clint = Cli::parse();

    let (control_tx, control_rx) = mpsc::channel::<ControlMessage>();
    if let Err(err) = spawn_listener(control_tx) {
        return err.into();
    }

    match Scanner::try_new(clint, control_rx) {
        Ok(scanner) => match scanner.run() {
            Ok(_ips) => ExitCode::from(ScannerExitCode::Ok as u8),
            Err(e) => e.into(),
        },
        Err(e) => e.into(),
    }
}