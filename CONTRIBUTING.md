# Contributing

[README](README.md) · [Adapter reference](docs/adapters.md) · [Security](SECURITY.md)

Develop and test against disposable stores with synthetic certificates. Never use
your system trust store, browser profile or a real device as a test fixture. Report
security issues using the guidance in [SECURITY.md](SECURITY.md).

## Local checks

```bash
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv build
```

Tests exercise the actual local helper, temporary files, process-death recovery,
mode/owner/group/xattr/ACL preservation, optimistic concurrency, input validation,
and MCP tools over both in-memory and real stdio connections. Optional native SSH tests start a private
loopback server with disposable authentication keys and pinned host keys. They
exercise file and p11-kit apply/rollback, source conflicts and host-key mismatch
rejection without touching system SSH configuration or a real device. Set
`EMUDHRA_TEST_SSHD` to the local sshd executable to enable them. CI runs on Linux
with Python 3.12 and 3.13.

## Native test coverage

Tests that require unavailable tools or a different operating system are skipped.
Use `uv run pytest -q -rs` to see why. A passing Linux run alone does not establish
Windows or macOS support; inspect the relevant native workflow too.

| Fixture | Requirement or environment variable |
| --- | --- |
| Java stores and PKIX chains | JDK 17+; `EMUDHRA_JAVA` selects the `java` executable |
| NSS | Mozilla NSS `certutil` and `vfychain` on PATH |
| Debian | Installed `update-ca-certificates` and OpenSSL; tests use temporary paths |
| p11-kit | `EMUDHRA_TEST_TRUST` and `EMUDHRA_TEST_P11_MODULE` select native tools |
| BKS interoperability | `EMUDHRA_TEST_BC_JAR` points to the hash-checked test provider; JDK required |
| Loopback SSH | `EMUDHRA_TEST_SSHD` points to `sshd`; disposable keys and pinned host keys |
| Windows | Native runner; custom stores and memory stores only |
| Apple profiles | Native macOS `plutil`; no profile installation |

The [Linux](.github/workflows/ci.yml), [Java](.github/workflows/java-native.yml),
[Fedora](.github/workflows/fedora-native.yml), [Windows](.github/workflows/windows-native.yml)
and [macOS](.github/workflows/macos-native.yml) workflows record tool setup and platform
coverage. The Bouncy Castle provider is a test dependency only. Use the pinned download
and checksum in CI when reproducing those tests.

[tools/probe_fedora.py](tools/probe_fedora.py) exercises copied Fedora sources inside
an explicitly marked disposable rootfs. Its userspace results do not validate
SELinux enforcement or a real device's filesystem and application behavior.

## Updating the incident policy

To update policy, retrieve the official announcement at the revision in
`tools/import_incident.py`, save it locally, and run:

```bash
uv run python tools/import_incident.py /path/to/Announcements.md
```

Review the manifest diff and source before committing. The importer rejects an
unexpected table size, category counts, and input bytes differing from the pinned
content hash. To track a new advisory revision, deliberately update its pinned
revision, content hash, importer expectations, tests, and reviewed date together.

Certificate parsing deliberately fails closed for malformed bundles. Cryptography
is bounded to the tested major-version range because future stricter X.509 parsing
may reject legacy certificates in system bundles; review compatibility before
raising that bound. The committed lockfile fixes the development/CI environment.

## Adding or changing an adapter

Keep the existing flow: explicit inventory, inspect, save a durable backup, bind a
plan to current state, apply a narrow change, verify, and recover. Match exact
certificate fingerprints; issuer names and aliases are display metadata.

An adapter contribution should include:

- An enforced format boundary that rejects unsupported content before mutation.
- Survivor checks for unrelated certificates, trust attributes and metadata.
- Apply, conflict, interrupted-write and rollback coverage on disposable fixtures.
- Native interoperability evidence where tools are available, with untested paths
  stated explicitly in the documentation and `list_adapters` output.
- Inventory examples and updates to the adapter reference and security model.

Native OS adapters should change persistent source policy rather than only generated
bundles. Do not register placeholder adapters. Review the adapter revision whenever
behavior changes: existing saved plans must either remain safe or be restricted to
rollback. Add focused regression tests for correctness fixes and report exactly
which platforms and native tools you exercised.

[ADAPTER_WORK.md](ADAPTER_WORK.md) is the historical implementation and validation
log. Use the README and adapter reference for current operator instructions.
