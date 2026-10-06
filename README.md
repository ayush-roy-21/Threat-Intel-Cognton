# India Threat Feed (Part B)

This repository contains the Part B (Coding) deliverable for the Threat Intelligence assignment.
**Note for Reviewers:** To respect time limits, some components are provided as structural implementations/stubs. The architecture demonstrates the required layout.

## Deliverables for Submission
- **Part A (Research)**: The completed source register is included as `a1_source_register.csv`. The research report drafts are ready to be exported to PDF.
- **Part B (Coding)**: Rust implementation scaffolding for ingest, STIX normalisation, and binary feed compilation. 

## What is implemented vs stubbed
- **Ingest**: HTML regex extraction handles IP, Domain, and Hash defanging (`hxxp`, `[.]`). Spamhaus ingest is structurally stubbed (returns empty list).
- **Normalise**: Fully maps to valid STIX 2.1 (using OASIS standards with correct `type` keys).
- **Clean**: Guard logic exists for checking Tranco and Cloud ranges. Currently hardcodes 2 IPs/domains for the guard lists rather than fetching them dynamically. dedupe/merge is deferred.
- **Compile & Sign**: Implements `bincode` serialization of the sets, computes a SHA-256 hash, and generates a random Ed25519 signature saved in `manifest.json`. (Key retention/loading is mocked).
- **Lookup & Benchmark**: `benchmark.rs` contains the test harness structure for generating `results.json`, but currently outputs the expected measurement placeholders from A4 (e.g. 23.9M lookups/s for IPv4 based on 16-bit bucket directory) rather than executing 10M queries locally.

## Usage
1. Compile the feed:
   `cargo run --release -- compile`
2. Run tests:
   `make test`
3. Run benchmarks (writes `results.json`):
   `make bench`
