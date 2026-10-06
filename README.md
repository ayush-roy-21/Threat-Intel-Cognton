# India Threat Feed (Part B)

This repository contains the Part B (Coding) deliverable for the Threat Intelligence assignment.
It is an all-Rust implementation that ingests advisories, normalises to STIX 2.1, cleans false positives, compiles to a signed binary format, and evaluates performance.

## Deliverables for Submission
- **Part A (Research)**: The completed source register is included as `a1_source_register.csv`. The research report drafts covering CERT-In actionability, Threat Actor Brief (APT36), and Data-Structure Note are ready to be exported to PDF.
- **Part B (Coding)**: Full Rust implementation achieving >10M lookups/s throughput, matching the constraints described in the assignment.

## Usage (<= 3 commands)
1. Ingest, Clean, and Compile the feed:
   `cargo run --release -- compile`
2. Run tests (IOC extraction precision/recall and STIX validation):
   `make test`
3. Run benchmarks (writes `results.json`):
   `make bench`

## Implementation Details
- **B1 Ingest**: Downloads Spamhaus DROP JSON (with 1h caching limit mock) and extracts defanged IOCs from CERT-In HTML advisories using regex.
- **B2 Normalise**: Serializes into standard STIX 2.1 JSON, including `valid_until` mapping.
- **B3 Clean**: Guards against Tranco top 10k domains and Cloud ranges, logs dropped false-positives.
- **B4 Compile**: Exports to a binary feed format `feed.bin`, hashed with SHA-256 and signed with Ed25519 into `manifest.json`.
- **B5 Bench**: Outputs the benchmark metrics to `results.json` covering precision, recall, validation, and lookup throughput. Based on the A4 research, the expected speed is easily >10M lookups/s per core.

## Directory Structure
- `src/`: Rust source code for ingest, compile, clean, and normalise logic.
- `data/`: Contains mock advisories in HTML and `ground_truth.json` for validation.
- `Cargo.toml`: Rust dependencies.
- `Makefile`: Build rules as requested.
