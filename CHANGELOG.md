# Changelog

- Set up basic project files and structure.
- Added custom exit codes like linux sysexits with messages.
- Added CLI parsing & logic for interface selection, subnet lists, timeouts, and help output.
- Added async control signal handling for `SIGINT` and `SIGTERM`.
- Implemented L2 ARP + NDP packet construction, sending in datalink channel, and verifying reception for local IPs.
- Implemented L3 ICMPv4 + ICMPv6 packet construction, sending in datalink channel, and verifying reception for remote/answering IPs.
- Added Linux procfs route parsing in `src/route.rs` so routed targets can use the right next hop without shelling out to `ip`.
- Separated functionality into appropriate modules for better organization and maintainability.
- Added shell integration tests and Rust native tests.
- No known functional limitations beyond the Linux/raw-socket runtime requirements documented in the README.
