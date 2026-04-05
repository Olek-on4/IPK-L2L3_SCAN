//! Command Line Interface definition and parsing for the L2L3 scanner.
use ipnet::IpNet;

/// Command Line Interface arguments for the scanner.
#[derive(Debug, clap::Parser)]
#[command(name = "l2l3-scanner")]
#[command(about = "Scans for available IpV4 and IpV6 addresses on provided interface", long_about = None)]
#[command(help_template = "{about}\n\nSynopsis:\n  ./ipk-L2L3-scan -i INTERFACE [-s SUBNET]... [-w TIMEOUT] [-h | --help]\n\n{all-args}\n{after-help}")]
pub struct Cli {
    /// Available network interface to scan (e.g. 'wlan0'), or list interfaces if not provided.
    #[arg(short, value_name = "INTERFACE", num_args = 0..=1)]
    pub interface: Option<Option<String>>,

    /// List of subnet values defining scanning ranges (e.g. '192.168.1.0/24').
    #[arg(short, value_name = "SUBNET")]
    pub subnets: Option<Vec<IpNet>>,

    /// Program timeout value in milliseconds.
    #[arg(short = 'w', default_value_t = 1000)]
    pub timeout: u64,
}
