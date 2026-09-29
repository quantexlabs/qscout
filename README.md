# qscout

Offline evidence fusion for post-quantum cryptography inventory: an open-source tool by **QuanteX Labs Inc.** that helps teams see where their systems rely on cryptography that quantum computers could break, and plan the migration.

qscout is a planning aid. It does not certify compliance with any standard, and it is not legal or security-assurance advice. No clients or deployments are claimed.

## Open by design

**We build in the open.** QuanteX Labs Inc. publishes its tools, methods and learning materials under open licences, so public-interest teams can use them, check how they work and adapt them freely. Open work is easier to trust, because anyone can see exactly how a result is produced. Code is licensed under Apache-2.0.

**Our own work, and only ours.** Everything in this repository was created by QuanteX Labs Inc. from public data and synthetic examples. It contains no client data, no client projects, and no one else's confidential information or intellectual property.

qscout correlates cryptographic findings from local source code, configuration files,
X.509 certificates, dependency manifests, and imported endpoint scan results
(`testssl.sh`, `ssh-audit`, sonar-cryptography/CBOMkit JSON). Output is CycloneDX 1.6
CBOM (validated against the vendored official schema for representative scans) with an
accessible HTML report and explainable priority scoring.

## Requirements

- Python 3.11 or 3.12
- OpenSSL (for certificate test fixtures only)

## Install

```bash
pip install git+https://github.com/quantexlabs/qscout.git
```

Development install:

```bash
pip install -e ".[dev]"
```

## Usage

Scan a local path (ownership attestation required):

```bash
qscout scan ./my-app --attest-ownership --output cbom.json --report report.html
```

Import endpoint scan results:

```bash
qscout import-endpoint ./testssl-results.json --attest-ownership --output cbom.json
```

Prioritize findings with organizational context:

```bash
qscout prioritize cbom.json --context systems.yaml --output prioritized.json
```

Generate a report:

```bash
qscout report cbom.json --output report.html --context systems.yaml
```

### systems.yaml

```yaml
systems:
  - system_id: web-app-01
    name: Customer Portal
    criticality: 5          # 1-5
    confidentiality_years: 15
    exposure: internet      # internet | partner | internal
```

## Check catalogue

| Check ID | Description |
|----------|-------------|
| CRYPTO-001 | RSA key size below 2048 bits |
| CRYPTO-002 | RSA encryption or key transport |
| CRYPTO-003 | DH or ECDH key agreement |
| CRYPTO-004 | RSA, ECDSA, or EdDSA signatures |
| CRYPTO-005 | DSA signatures |
| CRYPTO-006 | Hard-coded keys or PEM private keys |
| CRYPTO-007 | MD5 or SHA-1 for signatures or HMAC |
| CRYPTO-008 | Weak TLS configuration |
| CRYPTO-009 | X.509 certificate issues |
| CRYPTO-010 | Unresolved crypto library dependency |
| CRYPTO-011 | Post-quantum algorithm present (informational) |
| CRYPTO-012 | Stateful hash signatures (LMS/XMSS) |

Standards mapping uses "informed by" unless an exact citation applies.

## Safety

- `--attest-ownership` required for scan and import
- No network I/O when `PQC_INVENTORY_NO_NETWORK=1`
- Path traversal protection, bounded file reads on all parsers, safe YAML loading
- Full PEM private-key block redaction
- Structured scan errors and skipped-file reporting in CBOM and HTML output
- URL validation on endpoint locations before persistence and rendering
- Scan timeout uses a worker process (portable across platforms)

## CycloneDX conformance

qscout emits `cryptoProperties` with `assetType` and the appropriate
`algorithmProperties` or `certificateProperties` structures per CycloneDX 1.6.
The official JSON schema is vendored at `src/qscout/schemas/bom-1.6.schema.json`
(Apache-2.0, source: https://cyclonedx.org/schema/bom-1.6.schema.json).
CI validates representative CBOM output against this schema.

## Development

```bash
ruff check src tests
mypy src/qscout
source .venv/bin/activate && pyright
PQC_INVENTORY_NO_NETWORK=1 pytest --cov=qscout --cov-report=term-missing --cov-fail-under=90
pip install build && python -m build
python -m venv /tmp/qscout-venv && /tmp/qscout-venv/bin/pip install dist/*.whl
/tmp/qscout-venv/bin/qscout --version
```

## License

Apache-2.0. Copyright 2025 QuanteX Labs Inc.
