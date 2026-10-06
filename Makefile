.PHONY: all test bench clean

all: build

build:
	cargo build --release

test:
	cargo run --release -- test-extraction
	cargo run --release -- validate-stix

bench:
	cargo run --release -- bench

clean:
	cargo clean
	rm -f feed.json feed.bin manifest.json results.json
