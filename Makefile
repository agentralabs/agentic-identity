.PHONY: all build build-debug test test-unit test-stress test-integration lint lint-fmt lint-clippy bench clean install

all: build

build:
	cargo build --workspace --release

build-debug:
	cargo build --workspace

test: test-unit test-stress test-integration

test-unit:
	cargo test --lib

test-stress:
	cargo test --test "*stress*" --test "*concurrent*" --test "*multi_*" --test "*chain*" --test "*depth*"

test-integration:
	cargo test --test "*workflow*" --test "*cli*"

lint: lint-fmt lint-clippy

lint-fmt:
	cargo fmt --all -- --check

lint-clippy:
	cargo clippy --workspace --all-targets -- -D warnings

bench:
	cargo bench

clean:
	cargo clean

install:
	cargo install --path crates/agentic-identity-cli
	cargo install --path crates/agentic-identity-mcp
