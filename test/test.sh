#!/usr/bin/env bash

set -uo pipefail

HOST_IFACE="test0"
PEER_IFACE="test1"

ROUTER_IFACE="test2"
REMOTE_IFACE="test3"

NS_NAME="target_ns"
REMOTE_NS="remote_ns"

V4_HOST="192.168.16.1/20"
V6_HOST="fd00:cafe::1/64"

ROUTER_V4="192.168.16.254/20"
ROUTER_V6="fd00:cafe::fe/64"

REMOTE_ROUTER_V4S=("198.51.100.1/24" "198.51.101.1/24" "198.51.102.1/24")
REMOTE_ROUTER_V6S=("2001:db8:1::1/64" "2001:db8:2::1/64" "2001:db8:3::1/64")

LOCAL_V4_SUBNETS=("192.168.16.0/29" "192.168.20.0/29" "192.168.24.0/29")
LOCAL_V4_OUTSIDE="192.168.28.2"

LOCAL_V6_SUBNETS=("fd00:cafe::/125" "fd00:cafe::8/125" "fd00:cafe::10/125")
LOCAL_V6_OUTSIDE="fd00:cafe::18"

REMOTE_V4_SUBNETS=("198.51.100.0/29" "198.51.101.0/29" "198.51.102.0/29")
REMOTE_V4_OUTSIDE="198.51.103.2"

REMOTE_V6_SUBNETS=("2001:db8:1::/125" "2001:db8:2::/125" "2001:db8:3::/125")
REMOTE_V6_OUTSIDE="2001:db8:4::2"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER_BIN="${ROOT_DIR}/ipk-L2L3-scan"

GREEN="\033[0;32m"
RED="\033[0;31m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RESET="\033[0m"

PASSED=0
FAILED=0
SUITES=0

# Section header
print_header() {
	printf "\n${BLUE}== %s ==${RESET}\n" "$1"
}

# Report successful check and increment counter
ok() {
	printf "${GREEN}[PASS]${RESET} %-40s [%s ms]\n" "$1" "$2"
	PASSED=$((PASSED + 1))
}

# Report failed check and increment counter
fail() {
	printf "${RED}[FAIL]${RESET} %-40s [%s ms]\n" "$1" "$2"
	FAILED=$((FAILED + 1))
}

# Start a new test suite block
suite() {
	SUITES=$((SUITES + 1))
	print_header "Suite ${SUITES}: $1"
}

# Run one check command and print PASS/FAIL
chk() {
	local name="$1"
	shift
	local started_at ended_at elapsed
	started_at="$(date +%s%3N)"

	if "$@"; then
		ended_at="$(date +%s%3N)"
		elapsed=$((ended_at - started_at))
		ok "$name" "$elapsed"
	else
		ended_at="$(date +%s%3N)"
		elapsed=$((ended_at - started_at))
		fail "$name" "$elapsed"
	fi
}

# Basic CLI checks that do not require network setup.
cli_help_ok() {
	local output rc
	output="$($SCANNER_BIN --help 2>&1)"
	rc=$?
	[[ "$rc" -eq 0 && "$output" == *"Synopsis:"* && "$output" == *"Available network interface to scan"* ]]
}

cli_list_ok() {
	local output rc
	output="$($SCANNER_BIN -i 2>&1)"
	rc=$?
	[[ "$rc" -eq 0 && "$output" == *"Available interfaces:"* ]]
}

cli_no_args_fail() {
	local output rc
	output="$($SCANNER_BIN 2>&1)"
	rc=$?
	[[ "$rc" -ne 0 && "$output" == *"No arguments provided"* ]]
}

cli_unknown_iface_fail() {
	local output rc
	output="$($SCANNER_BIN -i definitely-not-an-interface -s 192.168.1.0/24 2>&1)"
	rc=$?
	[[ "$rc" -ne 0 && "$output" == *"Interface 'definitely-not-an-interface' not found"* ]]
}

cli_missing_subnet_fail() {
	local output rc
	output="$($SCANNER_BIN -i lo 2>&1)"
	rc=$?
	[[ "$rc" -ne 0 && "$output" == *"No subnets specified"* ]]
}

# Run the non-root CLI smoke suite.
suite_cli() {
	suite "CLI"
	chk "Help output is available" cli_help_ok
	chk "Interface listing works" cli_list_ok
	chk "Missing arguments fail" cli_no_args_fail
	chk "Unknown interface fails" cli_unknown_iface_fail
	chk "Missing subnet list fails" cli_missing_subnet_fail
}

# Run the scanner once and capture stdout/stderr for assertions.
scan_run() {
	local scan_timeout_ms="$1"
	shift
	(cd "$ROOT_DIR" && sudo "$SCANNER_BIN" -i "$HOST_IFACE" -w "$scan_timeout_ms" "$@" 2>&1)
}

# Assert that output matches every regex.
assert_regexes() {
	local output="$1"
	shift

	local regex
	for regex in "$@"; do
		grep -Eq "$regex" <<<"$output" || return 1
	done

	return 0
}

# Assert that output does not contain the provided fragment.
assert_absent() {
	local output="$1"
	local needle="$2"
	! grep -Fq "$needle" <<<"$output"
}

# Assert that each line appears exactly once or at least once in the output.
assert_lines() {
	local output="$1"
	shift

	local line
	for line in "$@"; do
		grep -Fq "$line" <<<"$output" || return 1
	done

	return 0
}

# Return success if interface exists
has_if() {
	sudo ip link show "$1" >/dev/null 2>&1
}

# Return success if namespace exists
has_ns() {
	sudo ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

# Return success if the given interface exists in the named namespace.
has_ns_if() {
	sudo ip netns exec "$1" ip link show "$2" >/dev/null 2>&1
}

# Create or reuse the test network setup
net_up() {
	if has_if "$HOST_IFACE" && has_ns_if "$NS_NAME" "$PEER_IFACE" && has_ns_if "$NS_NAME" "$ROUTER_IFACE" && has_ns_if "$REMOTE_NS" "$REMOTE_IFACE"; then
		printf "${YELLOW}Network setup already exists, reusing it.${RESET}\n"
		return 0
	fi

	if has_if "$HOST_IFACE" || has_ns_if "$NS_NAME" "$PEER_IFACE" || has_ns_if "$NS_NAME" "$ROUTER_IFACE" || has_ns_if "$REMOTE_NS" "$REMOTE_IFACE"; then
		printf "${YELLOW}Partial network setup found, cleaning stale state first.${RESET}\n"
		net_down >/dev/null
	fi

	print_header "Setting Up veth Namespace Network"

	sudo ip link add "$HOST_IFACE" type veth peer name "$PEER_IFACE"
	sudo ip link add "$ROUTER_IFACE" type veth peer name "$REMOTE_IFACE"

	if command -v nmcli >/dev/null 2>&1; then
		sudo nmcli device set "$HOST_IFACE" managed no || true
		sudo nmcli device set "$PEER_IFACE" managed no || true
		sudo nmcli device set "$ROUTER_IFACE" managed no || true
		sudo nmcli device set "$REMOTE_IFACE" managed no || true
	fi

	sudo ip addr flush dev "$HOST_IFACE"
	sudo ip addr flush dev "$PEER_IFACE"
	sudo ip addr flush dev "$ROUTER_IFACE"
	sudo ip addr flush dev "$REMOTE_IFACE"

	sudo ip netns add "$NS_NAME"
	sudo ip netns add "$REMOTE_NS"
	sudo ip link set "$PEER_IFACE" netns "$NS_NAME"
	sudo ip link set "$ROUTER_IFACE" netns "$NS_NAME"
	sudo ip link set "$REMOTE_IFACE" netns "$REMOTE_NS"

	sudo ip addr add "$V4_HOST" dev "$HOST_IFACE"
	sudo ip -6 addr add "$V6_HOST" dev "$HOST_IFACE"
	sudo ip link set "$HOST_IFACE" up

	sudo ip netns exec "$NS_NAME" ip addr add "$ROUTER_V4" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip -6 addr add "$ROUTER_V6" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip addr add "192.168.16.2/20" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip addr add "192.168.16.3/20" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip addr add "192.168.20.2/20" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip addr add "192.168.20.3/20" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip addr add "192.168.24.2/20" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip addr add "192.168.24.3/20" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip -6 addr add "fd00:cafe::2/64" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip -6 addr add "fd00:cafe::3/64" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip -6 addr add "fd00:cafe::8/64" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip -6 addr add "fd00:cafe::9/64" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip -6 addr add "fd00:cafe::10/64" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip -6 addr add "fd00:cafe::11/64" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip link set "$PEER_IFACE" up
	for router_addr in "${REMOTE_ROUTER_V4S[@]}"; do
		sudo ip netns exec "$NS_NAME" ip addr add "$router_addr" dev "$ROUTER_IFACE"
	done
	for router_addr in "${REMOTE_ROUTER_V6S[@]}"; do
		sudo ip netns exec "$NS_NAME" ip -6 addr add "$router_addr" dev "$ROUTER_IFACE"
	done
	sudo ip netns exec "$NS_NAME" ip link set "$ROUTER_IFACE" up
	sudo ip netns exec "$NS_NAME" ip link set lo up
	sudo ip netns exec "$NS_NAME" sysctl -w net.ipv4.ip_forward=1 >/dev/null
	sudo ip netns exec "$NS_NAME" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

	sudo ip netns exec "$REMOTE_NS" ip addr add "198.51.100.2/24" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip addr add "198.51.100.3/24" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip addr add "198.51.101.2/24" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip addr add "198.51.101.3/24" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip addr add "198.51.102.2/24" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip addr add "198.51.102.3/24" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip -6 addr add "2001:db8:1::2/64" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip -6 addr add "2001:db8:1::3/64" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip -6 addr add "2001:db8:2::2/64" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip -6 addr add "2001:db8:2::3/64" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip -6 addr add "2001:db8:3::2/64" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip -6 addr add "2001:db8:3::3/64" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip link set "$REMOTE_IFACE" up
	sudo ip netns exec "$REMOTE_NS" ip link set lo up
	sudo ip netns exec "$REMOTE_NS" ip route add default via "198.51.100.1" dev "$REMOTE_IFACE"
	sudo ip netns exec "$REMOTE_NS" ip -6 route add default via "2001:db8:1::1" dev "$REMOTE_IFACE"

	# Wait until IPv6 address assignment finishes so the first NDP probe is stable.
	ipv6_ready "$HOST_IFACE" "${V6_HOST%%/*}" ""
	ipv6_ready "$PEER_IFACE" "${ROUTER_V6%%/*}" "$NS_NAME"
	ipv6_ready "$PEER_IFACE" "fd00:cafe::2" "$NS_NAME"
	ipv6_ready "$PEER_IFACE" "fd00:cafe::3" "$NS_NAME"
	ipv6_ready "$PEER_IFACE" "fd00:cafe::8" "$NS_NAME"
	ipv6_ready "$PEER_IFACE" "fd00:cafe::9" "$NS_NAME"
	ipv6_ready "$PEER_IFACE" "fd00:cafe::10" "$NS_NAME"
	ipv6_ready "$PEER_IFACE" "fd00:cafe::11" "$NS_NAME"
	ipv6_ready "$ROUTER_IFACE" "${REMOTE_ROUTER_V6S[0]%%/*}" "$NS_NAME"
	ipv6_ready "$REMOTE_IFACE" "2001:db8:1::2" "$REMOTE_NS"
	ipv6_ready "$REMOTE_IFACE" "2001:db8:1::3" "$REMOTE_NS"
	ipv6_ready "$REMOTE_IFACE" "2001:db8:2::2" "$REMOTE_NS"
	ipv6_ready "$REMOTE_IFACE" "2001:db8:2::3" "$REMOTE_NS"
	ipv6_ready "$REMOTE_IFACE" "2001:db8:3::2" "$REMOTE_NS"
	ipv6_ready "$REMOTE_IFACE" "2001:db8:3::3" "$REMOTE_NS"
}

# Wait until an IPv6 address is present and no longer tentative.
ipv6_ready() {
	local iface="$1"
	local addr="$2"
	local ns_name="$3"
	local deadline=$((SECONDS + 5))
	local output

	while (( SECONDS < deadline )); do
		if [[ -n "$ns_name" ]]; then
			output="$(sudo ip netns exec "$ns_name" ip -6 addr show dev "$iface" 2>/dev/null || true)"
		else
			output="$(sudo ip -6 addr show dev "$iface" 2>/dev/null || true)"
		fi

		if grep -Fq "$addr" <<<"$output" && ! grep -Fq "tentative" <<<"$output"; then
			return 0
		fi

		sleep 0.1
		done

	printf "${YELLOW}[WARN]${RESET} IPv6 address %s on %s did not settle in time\n" "$addr" "$iface"
	return 0
}

# Remove namespace and host-side veth if present
net_down() {
	if has_if "$HOST_IFACE"; then
		sudo ip link delete "$HOST_IFACE" || true
	fi

	if has_ns_if "$REMOTE_NS" "$REMOTE_IFACE"; then
		sudo ip netns exec "$REMOTE_NS" ip link delete "$REMOTE_IFACE" || true
	elif has_ns_if "$NS_NAME" "$ROUTER_IFACE"; then
		sudo ip netns exec "$NS_NAME" ip link delete "$ROUTER_IFACE" || true
	fi

	if has_ns "$NS_NAME"; then
		sudo ip netns delete "$NS_NAME" || true
	fi

	if has_ns "$REMOTE_NS"; then
		sudo ip netns delete "$REMOTE_NS" || true
	fi
}

local_v4_ok() {
	local output rc
	output="$(scan_run 1000 -s "${LOCAL_V4_SUBNETS[0]}" -s "${LOCAL_V4_SUBNETS[1]}" -s "${LOCAL_V4_SUBNETS[2]}")"
	rc=$?
	[[ "$rc" -eq 0 ]] || return 1
	assert_regexes "$output" \
		'^192\.168\.16\.2[[:space:]]+arp[[:space:]]+OK.*icmpv4[[:space:]]+OK$' \
		'^192\.168\.16\.3[[:space:]]+arp[[:space:]]+OK.*icmpv4[[:space:]]+OK$' \
		'^192\.168\.20\.2[[:space:]]+arp[[:space:]]+OK.*icmpv4[[:space:]]+OK$' \
		'^192\.168\.20\.3[[:space:]]+arp[[:space:]]+OK.*icmpv4[[:space:]]+OK$' \
		'^192\.168\.24\.2[[:space:]]+arp[[:space:]]+OK.*icmpv4[[:space:]]+OK$' \
		'^192\.168\.24\.3[[:space:]]+arp[[:space:]]+OK.*icmpv4[[:space:]]+OK$'
	assert_lines "$output" \
		"192.168.16.2 arp OK" \
		"192.168.16.3 arp OK" \
		"192.168.20.2 arp OK" \
		"192.168.20.3 arp OK" \
		"192.168.24.2 arp OK" \
		"192.168.24.3 arp OK"
	assert_absent "$output" "$LOCAL_V4_OUTSIDE"
}

local_v6_ok() {
	local output rc
	output="$(scan_run 1000 -s "${LOCAL_V6_SUBNETS[0]}" -s "${LOCAL_V6_SUBNETS[1]}" -s "${LOCAL_V6_SUBNETS[2]}")"
	rc=$?
	[[ "$rc" -eq 0 ]] || return 1
	assert_regexes "$output" \
		'^fd00:cafe::2[[:space:]]+ndp[[:space:]]+OK.*icmpv6[[:space:]]+OK$' \
		'^fd00:cafe::3[[:space:]]+ndp[[:space:]]+OK.*icmpv6[[:space:]]+OK$' \
		'^fd00:cafe::8[[:space:]]+ndp[[:space:]]+OK.*icmpv6[[:space:]]+OK$' \
		'^fd00:cafe::9[[:space:]]+ndp[[:space:]]+OK.*icmpv6[[:space:]]+OK$' \
		'^fd00:cafe::10[[:space:]]+ndp[[:space:]]+OK.*icmpv6[[:space:]]+OK$' \
		'^fd00:cafe::11[[:space:]]+ndp[[:space:]]+OK.*icmpv6[[:space:]]+OK$'
	assert_lines "$output" \
		"fd00:cafe::2 ndp OK" \
		"fd00:cafe::3 ndp OK" \
		"fd00:cafe::8 ndp OK" \
		"fd00:cafe::9 ndp OK" \
		"fd00:cafe::10 ndp OK" \
		"fd00:cafe::11 ndp OK"
	assert_absent "$output" "$LOCAL_V6_OUTSIDE"
}

remote_v4_ok() {
	local output rc
	output="$(scan_run 1500 -s "${REMOTE_V4_SUBNETS[0]}" -s "${REMOTE_V4_SUBNETS[1]}" -s "${REMOTE_V4_SUBNETS[2]}")"
	rc=$?
	[[ "$rc" -eq 0 ]] || return 1
	assert_regexes "$output" \
		'^198\.51\.100\.2[[:space:]]+arp[[:space:]]+FAIL,[[:space:]]+icmpv4[[:space:]]+OK$' \
		'^198\.51\.101\.2[[:space:]]+arp[[:space:]]+FAIL,[[:space:]]+icmpv4[[:space:]]+OK$' \
		'^198\.51\.102\.2[[:space:]]+arp[[:space:]]+FAIL,[[:space:]]+icmpv4[[:space:]]+OK$'
	assert_lines "$output" \
		"198.51.100.2 arp FAIL, icmpv4 OK" \
		"198.51.101.2 arp FAIL, icmpv4 OK" \
		"198.51.102.2 arp FAIL, icmpv4 OK"
	assert_absent "$output" "$REMOTE_V4_OUTSIDE"
}

remote_v6_ok() {
	local output rc
	output="$(scan_run 1500 -s "${REMOTE_V6_SUBNETS[0]}" -s "${REMOTE_V6_SUBNETS[1]}" -s "${REMOTE_V6_SUBNETS[2]}")"
	rc=$?
	[[ "$rc" -eq 0 ]] || return 1
	assert_regexes "$output" \
		'^2001:db8:1::2[[:space:]]+ndp[[:space:]]+FAIL,[[:space:]]+icmpv6[[:space:]]+OK$' \
		'^2001:db8:2::2[[:space:]]+ndp[[:space:]]+FAIL,[[:space:]]+icmpv6[[:space:]]+OK$' \
		'^2001:db8:3::2[[:space:]]+ndp[[:space:]]+FAIL,[[:space:]]+icmpv6[[:space:]]+OK$'
	assert_lines "$output" \
		"2001:db8:1::2 ndp FAIL, icmpv6 OK" \
		"2001:db8:2::2 ndp FAIL, icmpv6 OK" \
		"2001:db8:3::2 ndp FAIL, icmpv6 OK"
	assert_absent "$output" "$REMOTE_V6_OUTSIDE"
}

# Basic checks that test network setup is usable
suite_env() {
	suite "Setup check"
	local before_failed="$FAILED"

	chk "Host interface exists" has_if "$HOST_IFACE"
	chk "Router interface exists" has_ns_if "$NS_NAME" "$ROUTER_IFACE"
	chk "Namespace exists" has_ns "$NS_NAME"
	chk "Remote namespace exists" has_ns "$REMOTE_NS"
	chk "Remote interface exists" has_ns_if "$REMOTE_NS" "$REMOTE_IFACE"
	chk "IPv4 on host interface" bash -lc "sudo ip -4 addr show dev '$HOST_IFACE' | grep -q '${V4_HOST%%/*}'"
	chk "IPv6 on host interface" bash -lc "sudo ip -6 addr show dev '$HOST_IFACE' | grep -q '${V6_HOST%%/*}'"

	if (( FAILED > before_failed )); then
		printf "${RED}Setup is incorrect; skipping scanner suites.${RESET}\n"
		return 1
	fi

	return 0
}

# Composite local and remote target suites
suite_targets() {
	suite "Target coverage"
	chk "Local IPv4 - {OK, OK}" local_v4_ok
	chk "Local IPv6 - {OK, OK}" local_v6_ok
	chk "Remote IPv4 - {FAIL, OK}" remote_v4_ok
	chk "Remote IPv6 - {FAIL, OK}" remote_v6_ok
}

# Print final summary and return non-zero on failure
sum_up() {
	print_header "Test Summary"
	printf "Suites: %d\n" "$SUITES"
	printf "Passed: %d\n" "$PASSED"
	printf "Failed: %d\n" "$FAILED"

	if [[ "$FAILED" -eq 0 ]]; then
		printf "${GREEN}All suites passed.${RESET}\n"
		return 0
	fi

	printf "${RED}Some checks failed.${RESET}\n"
	return 1
}

# Print command usage help
help_msg() {
	cat <<EOF
Usage: $0 [setup|run|cleanup]

setup   create veth + namespace network setup if missing
run     setup, run suites, print summary, cleanup
cleanup remove namespace and interfaces

Examples:
	$0 run
	$0 setup
	$0 cleanup
EOF
}

# Main command dispatcher
main() {
	local cmd="${1:-run}"
	shift || true

	if [[ ! -x "$SCANNER_BIN" ]]; then
		(cd "$ROOT_DIR" && make) || return 1
	fi

	case "$cmd" in
		setup)
			net_up
			;;
		run)
			suite_cli
			net_up
			if suite_env; then
				suite_targets
			fi
			local rc=0
			sum_up || rc=$?
			net_down
			return "$rc"
			;;
		cleanup)
			net_down
			;;
		*)
			help_msg
			return 2
			;;
	esac
}

main "$@"
