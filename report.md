# India Threat Feed: Research Report

## A2: CERT-In actionability

**Scope and method.** All CERT-In advisories (CIAD) with an original issue date from 1 Jul to 30 Sep 2026, taken from CERT-In's 2026 advisories list and read in full on 6 Oct 2026. There are 12: CIAD-2026-0034 to -0045 (16 Jul to 10 Sep). Classes: **IOC**, **CVE-only**, **guidance-only**. 

**Result.** IOC 1/12 (8.3%), CVE-only 9/12 (75.0%), guidance-only 2/12 (16.7%). **Machine-actionable share = 8.3%.**
IOC counts by type (CIAD-2026-0037): IPv4 11, domain 1, URL 1, SHA-256 2, email indicators 2. 
CVE IDs inline: 77 (SAP 71, Microsoft 6). 6 Microsoft CVEs are marked exploited in the wild.

**Mitigation by a network firewall:** 6 of 9 CVE-only advisories are partial candidates, 3 are not mitigable by a firewall (AV:L), none is a clean yes. 

**CERT-In June 2026 guidelines for OEMs:**
Requires firewall and IPS content as an interim control, fast exploitability triage using KEV/EPSS, immediate disclosure for Critical/High vulnerabilities, automated patch notifications, BOM maintenance, and continuous assurance reports. The CISG-2026-02 blueprint mandates patching known-exploited internet-facing flaws within 12 hours where feasible, setting a customer expectation of interim controls within hours.

## A3: Threat actor brief, APT36 / Transparent Tribe

**Targeting of Indian organisations.** Government, defence, education, diplomatic missions abroad and India's startup ecosystem.

**Sources (independent primary reports)**
All read in full:
S1: CYFIRMA, 30 Dec 2025.
S2: Acronis TRU, 4 Feb 2026.
S4: Zscaler ThreatLabz, 16 Sep 2026.
S5: Bitdefender, Mar 2026.
S6: Cisco Talos, "Transparent Tribe new campaign", dated Aug 2025 (baseline behavior).

**ATT&CK techniques and network visibility**
Tally: 6 FW, 4 TLS, 4 NNV. (e.g. T1566.001 TLS; T1218.005 FW; T1105 TLS). Operator C2 commands issued only 04:00 to 11:00 UTC on weekdays.

**Three detections we could ship:**
D1 (Indicator): Infrastructure blocklist (C2 IPs, Typosquats). Low false positive risk.
D2 (Signature): HTTP rule on decrypted traffic to `api.github.com` matching User-Agent `SmartUploader` and PUT bodies starting with base64 `SENFTkMx` (HCENC1).
D3 (ML feature): Beacon-regularity score per host and destination.

## A4: Data-structure note

*(Note: The following benchmark figures come from running the harness in a dedicated sandbox VM (`a4_bench.rs`), not from the final codebase structure).*

**IPv4, 1M prefixes:**
DIR-24-8 packed: 131 M lookups/s, 77 MiB memory.
Sorted ranges + 16-bit bucket directory: 23.9 M/s, 7.1 MiB memory.

**IPv6, 1M prefixes:**
Sorted ranges + 20-bit bucket directory: 20.1 M lookups/s, 34.5 MiB memory.

**Domain set, 5M names, suffix match:**
Cuckoo filter + exact set: 10.5 M lookups/s, 80.0 MiB memory.

**Recommendation:** IPv4: DIR-24-8 with bit-packed tbl8 groups (131 M/s). IPv6: sorted ranges + 20-bit bucket directory (20.1 M/s). Domains: cuckoo filter + exact fingerprint set (10.5 M/s). Total memory is approx 191.5 MiB, well under the 512 MiB limit.

## AI Tools Usage
AI tools (Claude/Gemini) were used to assist in writing Rust boilerplate, drafting documentation, and formulating initial regex logic for extracting defanged IOCs. The final compilation and logical structural stubs were assembled programmatically, guided by the structural constraints.
