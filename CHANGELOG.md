# Changelog

All notable changes to qscout are documented in this file.

## [0.2.0] - 2025-09-28

### Fixed

- CycloneDX 1.6 CBOM output now uses `cryptoProperties.assetType` with proper
  `algorithmProperties` and `certificateProperties` structures; schema validation
  added against the vendored official 1.6 JSON schema
- Scanner and parser failures are recorded as structured errors instead of silent
  empty evidence; error and skipped-file counts appear in CBOM and HTML output
- `resolve_safe_path` no longer accepts paths via string-prefix fallback
- PEM private-key redaction now removes the entire block including body and END marker
- X.509 certificate classification: weak keys, weak signatures, and expiry are separate;
  classical keys map to CRYPTO-004 instead of CRYPTO-009
- RSA key-size handling preserves unknown sizes; SSH audit no longer infers 2048 bits
- Hybrid cryptography (e.g. ML-KEM + ECDH) is detected and reported
- Algorithm parameter sets preserved (e.g. SLH-DSA-SHA2-128s); AES/SHA classified
- All parser reads are bounded; malformed JSON returns structured errors
- CBOM round-trip preserves severity, result, algorithm, metadata, and components
- URL validation wired into endpoint locations and report rendering
- Scan timeout uses a worker process instead of Unix-only SIGALRM

### Added

- Vendored CycloneDX 1.6 JSON schema with licence file
- Regression tests for schema validation, redaction, path traversal, parser errors,
  hybrid detection, CBOM round-trip, and hostile HTML output
- README "Open by design" section

## [0.1.0] - 2025-09-28

### Added

- Initial MVP release
- CLI commands: `scan`, `import-endpoint`, `prioritize`, `report`
- Offline evidence fusion from source, configs, certificates, manifests
- Import adapters for testssl.sh, ssh-audit, and sonar-cryptography JSON
- CycloneDX 1.6 CBOM export
- Twelve checks (CRYPTO-001 through CRYPTO-012) mapped to NIST FIPS 203/204/205,
  SP 800-208, and CCCS guidance
- Explainable priority scoring with `systems.yaml` context
- Accessible HTML report generation
- Security controls: URL validation, path traversal protection, safe YAML,
  bounded file reads, secret redaction
