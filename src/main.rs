//! L2L3-scanner: Scans for available IPv4 and IPv6 addresses on a specified network interface.

// Suppress non-idiomatic warning, such name is required
#![allow(non_snake_case)]

use std::process::ExitCode;
use std::sync::mpsc;

use clap::Parser;

use ipk_l2l3_scan::cli::Cli;
use ipk_l2l3_scan::format::format_scan_result;
use ipk_l2l3_scan::model::{ControlMessage, ScannerExitCode};
use ipk_l2l3_scan::network::spawn_listener;
use ipk_l2l3_scan::scanner::Scanner;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Create channel for async signal handling
    let (control_tx, control_rx) = mpsc::channel::<ControlMessage>();
    if let Err(err) = spawn_listener(control_tx) {
        return err.into();
    }

    // Try creating scanner from CLI args and reading handle
    match Scanner::try_new(cli, control_rx) {
        Ok(scanner) => {
            // Print networks/subnets that are going to be scanned
            println!("Scanning ranges:");
            scanner.print_nets();
            println!();

            match scanner.run() {
                Ok(matches) => {
                    // If ran successfuly, print results in the required format
                    for addr in scanner.networks().iter().flat_map(|net| net.hosts()) {
                        println!("{}", format_scan_result(&addr, matches.get(&addr)));
                    }

                    ExitCode::from(ScannerExitCode::Ok as u8)
                }
                Err(err) => err.into(),
            }
        }
        Err(err) => err.into(),
    }
}
