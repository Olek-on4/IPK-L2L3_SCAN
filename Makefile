BIN := L2L3-scan
RELEASE_BIN := src/target/release/$(BIN)

all: build

# Required by evaluation scripts: print only devShell name.
NixDevShellName:
	@echo rust

build:
	cargo build --release
	cp $(RELEASE_BIN) ./$(BIN)
	chmod +x ./$(BIN)

run:
	cargo run --release --bin $(BIN) --

test:
	cargo test --all --all-targets

check:
	cargo check --all-targets

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

clean:
	cargo clean
	rm -f ./$(BIN)

nix-clean:
	rm -rf .vm
	nix-collect-garbage -d

.PHONY: all NixDevShellName build run test check fmt clippy clean nix-clean