# L2L3-scanner

`ipk-L2L3-scan` is a Rust implementation of the IPK Project 1 DELTA scanner. It discovers IPv4 and IPv6 hosts on a chosen interface by combining layer 2 discovery (ARP / NDP) with layer 3 reachability probes (ICMPv4 / ICMPv6).

The project is designed to run in the reference Linux environment used for evaluation and uses raw Ethernet frames through `pnet`.

## Build

The course evaluator expects the project to activate the `rust` Nix dev shell.

```bash
make NixDevShellName
```

Build the release binary in the repository root:

```bash
make build
```

Other present developer commands:

```bash
make check
make fmt
make clippy
make test
```

To enter the reference Rust environment manually:

```bash
nix develop --refresh 'git+https://git.fit.vutbr.cz/NESFIT/dev-envs.git#rust'
```

## Run

Show usage:

```bash
./ipk-L2L3-scan --help
```

Help is always invoked when `-h` / `--help` is present anywhere in a correct command.

List interfaces:

```bash
./ipk-L2L3-scan -i
```

Scan one or more subnets:

```bash
sudo ./ipk-L2L3-scan -i eth0 -w 1000 -s 192.168.1.0/24 -s fd00:cafe::/120
```

By standard, program output goes to `stdout` and errors to `stderr`.

## Implemented Behavior

- `-h` / `--help` prints usage and exits successfully.
- `-i` without a value prints available interfaces and exits successfully.
- `-i <iface>` selects the interface to scan. Requires at least one `-s` option.
- Repeated `-s` options define the scan ranges.
- `-w` sets the timeout in milliseconds and defaults to `1000`.
- IPv4 targets are scanned with ARP and ICMPv4.
- IPv6 targets are scanned with NDP and ICMPv6.
- The program prints a scanning summary list first, then a blank line, then one result line per host in `<IP> {arp|ndp} {OK (<MAC>)|FAIL}, icmpv{4|6} {OK|FAIL}` format.
- Signals `SIGINT` and `SIGTERM` are periodically checked for shutdown.

## Design Decisions

- The scanner is implemented in Rust as a single binary, since I wanted to learn Rust and this project seemed like a good fit.
- Packet construction is done manually with `pnet` so the program can send and parse the exact Ethernet/IP/ICMP/ARP/NDP frames/packets required.
- Discovery is synchronous and deadline-based. The code sends requests, waits for timeout per read or whole subnet scan, and then collects layer results.
- A dedicated signal-listener thread forwards termination requests into the scan loop without blocking.
- The code is split across modules `cli.rs`, `format.rs`, `model.rs`, `network.rs`, `scanner.rs` to be utilized from `lib.rs` by `main.rs` for simple structure and organization.

### Environment

- Linux x86_64 reference-style environment.
- Nix dev shell: `rust`.
- Requires root privileges for raw sockets.

## Testing

### Requirements

- `ip` and network namespace setup for tests.
- Network configuraion: one host namespace, one local/router namespace, and one remote namespace connected with `veth` pairs.
- Utils used: `bash`, `iproute2`, `cargo`, `rustc`, `rustfmt`, `clippy`.

### How To Run

```bash
make test
```

The script in `test/test.sh` does this:

1. build the binary if needed,
2. set up the host-facing `test0` / `test1` pair,
3. add a second `veth` pair that connects the router namespace to a remote namespace,
4. assign multiple local and remote IPv4/IPv6 hosts across several subnets,
5. run a setup-only check first,
6. run the scanner against local `/20` targets and remote routed targets,
7. clean up the namespaces and interfaces.

After that, `cargo test --all-targets` runs the Rust unit tests in `src/`.

### Inputs, Expected Output, and Results

| Check | Input | Expected | Outcome |
| --- | --- | --- | --- |
| CLI help | `./ipk-L2L3-scan --help` | Usage text on `stdout`, exit `0` | Passed |
| CLI interface list | `./ipk-L2L3-scan -i` | Interface list on `stdout`, exit `0` | Passed |
| CLI errors | Missing args, unknown interface, missing subnet list | Non-zero exit code and readable error message on `stderr` | Passed |
| Setup check | Network namespace and `veth` setup | Host interface, router namespace, remote namespace, and IP setup are present | Passed |
| Local IPv4 - `{OK, OK}` | `-i test0 -s 192.168.16.0/29 -s 192.168.20.0/29 -s 192.168.24.0/29` | Multiple local hosts in each subnet respond with `arp OK` and `icmpv4 OK`, and the out-of-range host is absent | Passed |
| Local IPv6 - `{OK, OK}` | `-i test0 -s fd00:cafe::/125 -s fd00:cafe::8/125 -s fd00:cafe::10/125` | Multiple local hosts in each subnet respond with `ndp OK` and `icmpv6 OK`, and the out-of-range host is absent | Passed |
| Remote IPv4 - `{FAIL, OK}` | `-i test0 -s 198.51.100.0/29 -s 198.51.101.0/29 -s 198.51.102.0/29` | Remote hosts respond with `arp FAIL, icmpv4 OK` through the router namespace | Passed |
| Remote IPv6 - `{FAIL, OK}` | `-i test0 -s 2001:db8:1::/125 -s 2001:db8:2::/125 -s 2001:db8:3::/125` | Remote hosts respond with `ndp FAIL, icmpv6 OK` through the router namespace | Passed |

## Known Limitations

- The scanner is Linux-focused because it depends on raw datalink access and network namespaces.
- Running the tests requires elevated privileges.
- The test suite validates behavior against a controlled local `veth` setup; it does not replace manual verification on real network hardware.

## References

- [IPK project requirements](https://git.fit.vutbr.cz/NESFIT/IPK-Project-Guidelines)
- [Shared development environments](https://git.fit.vutbr.cz/NESFIT/dev-envs)
- [clap crate documentation](https://docs.rs/clap/)
- [pnet crate documentation](https://docs.rs/pnet/)
- [signal-hook crate documentation](https://docs.rs/signal-hook/)
- [Rust standard library](https://doc.rust-lang.org/std/)
