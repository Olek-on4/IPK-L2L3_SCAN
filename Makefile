BIN := ipk-L2L3-scan
RELEASE_BIN := target/release/$(BIN)

all: build

# Required by evaluation scripts: print only devShell name.
NixDevShellName:
	@echo rust

build:
	cargo build --release --bin $(BIN)
	cp $(RELEASE_BIN) ./$(BIN)
	chmod +x ./$(BIN)

run:
	cargo run --release --bin $(BIN) --

test-up:
	bash test/test.sh setup

test-down:
	bash test/test.sh cleanup

test:
	bash test/test.sh run
	cargo test --all-targets

check:
	cargo check --all-targets

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

zip:
	@echo TODO: Add NESFIT to gitea repo
	zip -r xhumeno00.zip Cargo.toml Cargo.lock *.md LICENSE Makefile src test

clean:
	cargo clean
	rm -f ./$(BIN)

nix-clean:
	rm -rf .vm
	nix-collect-garbage -d

.PHONY: all NixDevShellName build run test check fmt clippy clean nix-clean