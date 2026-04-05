#!/usr/bin/env bash

set -uo pipefail

HOST_IFACE="test0"
PEER_IFACE="test1"
NS_NAME="target_ns"
V4_HOST="192.168.1.1/24"
V4_PEER="192.168.1.2/24"
V6_HOST="fd00:cafe::1/64"
V6_PEER="fd00:cafe::2/64"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Default subnet lists per suite
DEFAULT_V4_SUBNETS=("192.168.1.2/32" "192.168.1.0/24")
DEFAULT_V6_SUBNETS=("fd00:cafe::2/128" "fd00:cafe::/64")

GREEN="\033[0;32m"
RED="\033[0;31m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RESET="\033[0m"

PASSED=0
FAILED=0
SUITES=0

# Section header
hdr() {
	printf "\n${BLUE}== %s ==${RESET}\n" "$1"
}

# Report successful check and increment counter
ok() {
	printf "${GREEN}[PASS]${RESET} %s\n" "$1"
	PASSED=$((PASSED + 1))
}

# Report failed check and increment counter
fail() {
	printf "${RED}[FAIL]${RESET} %s\n" "$1"
	FAILED=$((FAILED + 1))
}

# Start a new test suite block
suite() {
	SUITES=$((SUITES + 1))
	hdr "Suite ${SUITES}: $1"
}

# Run one check command and print PASS/FAIL
chk() {
	local name="$1"
	shift

	if "$@"; then
		ok "$name"
	else
		fail "$name"
	fi
}

# Return success if interface exists
has_if() {
	sudo ip link show "$1" >/dev/null 2>&1
}

# Return success if namespace exists
has_ns() {
	sudo ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

# Create or reuse the test network setup
net_up() {
	if has_if "$HOST_IFACE" && has_ns "$NS_NAME"; then
		printf "${YELLOW}Network setup already exists, reusing it.${RESET}\n"
		return 0
	fi

	if has_if "$HOST_IFACE" || has_ns "$NS_NAME"; then
		printf "${YELLOW}Partial network setup found, cleaning stale state first.${RESET}\n"
		net_down >/dev/null
	fi

	hdr "Setting Up veth Namespace Network"

	sudo ip link add "$HOST_IFACE" type veth peer name "$PEER_IFACE"

	if command -v nmcli >/dev/null 2>&1; then
		sudo nmcli device set "$HOST_IFACE" managed no || true
		sudo nmcli device set "$PEER_IFACE" managed no || true
	fi

	sudo ip addr flush dev "$HOST_IFACE"
	sudo ip addr flush dev "$PEER_IFACE"

	sudo ip netns add "$NS_NAME"
	sudo ip link set "$PEER_IFACE" netns "$NS_NAME"

	sudo ip addr add "$V4_HOST" dev "$HOST_IFACE"
	sudo ip -6 addr add "$V6_HOST" dev "$HOST_IFACE"
	sudo ip link set "$HOST_IFACE" up

	sudo ip netns exec "$NS_NAME" ip addr add "$V4_PEER" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip -6 addr add "$V6_PEER" dev "$PEER_IFACE"
	sudo ip netns exec "$NS_NAME" ip link set "$PEER_IFACE" up
	sudo ip netns exec "$NS_NAME" ip link set lo up
}

# Remove namespace and host-side veth if present
net_down() {
	if has_ns "$NS_NAME"; then
		sudo ip netns delete "$NS_NAME" || true
	fi

	if has_if "$HOST_IFACE"; then
		sudo ip link delete "$HOST_IFACE" || true
	fi
}

# Generic scanner suite executor
suite_scan() {
	local suite_name="$1"
	local peer_ip="$2"
	local proto_label="$3"
	shift 3
	local subnets=("$@")

	suite "$suite_name"
	chk "Suite has at least one subnet" test "${#subnets[@]}" -gt 0

	local subnet
	for subnet in "${subnets[@]}"; do
		local out
		out="$(cd "$ROOT_DIR" && sudo cargo run --quiet -- -i "$HOST_IFACE" -s "$subnet" 2>&1 || true)"

		chk "Subnet $subnet includes peer $peer_ip" grep -Eq "$peer_ip" <<<"$out"
		chk "Subnet $subnet includes ${proto_label} status" grep -Eq "$peer_ip.*${proto_label} (OK|FAIL)" <<<"$out"
	done
}

# Basic checks that test network setup is usable
suite_env() {
	suite "Environment"
	chk "Host interface exists" has_if "$HOST_IFACE"
	chk "Namespace exists" has_ns "$NS_NAME"
	chk "IPv4 on host interface" bash -lc "sudo ip -4 addr show dev '$HOST_IFACE' | grep -q '${V4_HOST%%/*}'"
	chk "IPv6 on host interface" bash -lc "sudo ip -6 addr show dev '$HOST_IFACE' | grep -q '${V6_HOST%%/*}'"
}

# Run default IPv4 subnet suite
suite_v4_def() {
	suite_scan "IPv4 default subnet suite" "${V4_PEER%%/*}" "arp" "${DEFAULT_V4_SUBNETS[@]}"
}

# Run default IPv6 subnet suite
suite_v6_def() {
	suite_scan "IPv6 default subnet suite" "${V6_PEER%%/*}" "ndp" "${DEFAULT_V6_SUBNETS[@]}"
}

# Split custom subnets to IPv4/IPv6 and run matching suites
suite_custom() {
	if [[ "$#" -eq 0 ]]; then
		return 0
	fi

	local v4_custom=()
	local v6_custom=()
	local subnet
	for subnet in "$@"; do
		if [[ "$subnet" == *":"* ]]; then
			v6_custom+=("$subnet")
		else
			v4_custom+=("$subnet")
		fi
	done

	if [[ "${#v4_custom[@]}" -gt 0 ]]; then
		suite_scan "IPv4 custom subnet suite" "${V4_PEER%%/*}" "arp" "${v4_custom[@]}"
	fi

	if [[ "${#v6_custom[@]}" -gt 0 ]]; then
		suite_scan "IPv6 custom subnet suite" "${V6_PEER%%/*}" "ndp" "${v6_custom[@]}"
	fi
}

# Print final summary and return non-zero on failure
sum_up() {
	hdr "Test Summary"
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
Usage: $0 [setup|run|cleanup] [optional-subnet ...]

setup   create veth + namespace network setup if missing
run     setup, run suites, print summary, cleanup
cleanup remove namespace and interfaces

Examples:
  $0 run
  $0 run 192.168.1.2/32 192.168.1.0/24 fd00:cafe::2/128 fd00:cafe::/64
EOF
}

# Main command dispatcher
main() {
	local cmd="${1:-run}"
	shift || true

	case "$cmd" in
		setup)
			net_up
			;;
		run)
			net_up
			suite_env
			suite_v4_def
			suite_v6_def
			suite_custom "$@"
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
