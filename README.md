# eMudhra Remover

**Audit and remediate incident-listed CA certificates with your preferred AI agent.**

eMudhra Remover is a Model Context Protocol (MCP) server for certificate trust stores
on devices you administer. Connect a stdio-capable MCP client, configure the stores
to inspect, and let your agent scan for exact certificate fingerprints, prepare a
reviewable plan, and apply a removal or explicit distrust change with rollback.

It starts with **writes disabled**. You choose the targets and enable remediation;
the agent works within that inventory. No model API key is required by the server.

[Get started](#quick-start) · [Supported stores](#supported-stores) ·
[Adapter reference](docs/adapters.md) · [Operations and recovery](docs/operations.md) ·
[Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## How it works

1. **Configure** the stores to manage on local Linux or SSH-accessible devices.
2. **Scan** against the bundled incident policy using exact certificate SHA-256 fingerprints.
3. **Plan** a change, saving the original state and affected certificates for review.
4. **Apply** an approved plan after enabling writes. The server checks for changes
   since planning and verifies the adapter's result.
5. **Recover** using saved snapshots if an operation is interrupted, or roll back
   when you need to restore prior trust.

Backups are committed before target writes. File replacements are atomic; updates
spanning multiple files or native store entries use adapter-specific recovery.
Applications may cache trust, so service reloads and application checks remain part
of your maintenance procedure.

## Supported stores

There are **14 implemented adapters**. The controller runs on Linux; Windows stores
are managed over SSH. Appliance and media-player support depends on access to a
supported editable store, Python and SSH.

| Store or format | What the adapter changes | Guide |
| --- | --- | --- |
| Debian / Ubuntu | Persistent package-CA deselection and native regeneration; hooks disabled | [Debian](docs/adapters.md#debian-and-ubuntu) |
| p11-kit / Fedora-style stores | Owned distrust policy, consolidated exports and hash directory | [p11-kit](docs/adapters.md#p11-kit-and-fedora) |
| Windows Root / CA | Adds exact certificates to physical Disallowed; source stores stay intact | [Windows](docs/adapters.md#windows-certificate-store) |
| NSS SQL | Explicit distrust in a closed, empty-password database without private keys | [NSS](docs/adapters.md#nss-sql-databases) |
| Java JKS, JCEKS, PKCS12 | Removes trusted-certificate entries from supported certificate-only stores | [Java](docs/adapters.md#java-trust-stores) |
| Bouncy Castle BKS v2 | Removes certificate entries and preserves surviving entry bytes | [BKS](docs/adapters.md#bks-v2-trust-stores) |
| Ordinary PEM | Removes matching certificates from an application-owned bundle | [PEM](docs/adapters.md#pem-bundles) |
| OpenSSL trusted PEM | Adds auxiliary rejection metadata in a bundle or individual CApath backing file | [OpenSSL](docs/adapters.md#openssl-trusted-pem) |
| Unsigned PKCS#7 / P7B | Removes certificates from a certificate-only collection | [PKCS#7](docs/adapters.md#pkcs7-collections) |
| Exported Windows SST | Removes certificates from an asserted positive-anchor collection | [SST](docs/adapters.md#windows-sst-exports) |
| Apple .mobileconfig | Removes certificate payloads from an unsigned certificate-only source file | [Apple profiles](docs/adapters.md#apple-certificate-profiles) |
| EDK2 HTTPS collections | Removes X509 entries from a collection file | [EDK2](docs/adapters.md#edk2-https-collections) |

**File changes affect only the configured file.** Apple profiles, SST and EDK2
collections are source/export artifacts; their adapters do not install profiles,
import stores or deploy firmware. Editing a generated CA bundle can be undone by
regeneration—use the native source-policy adapter where available.

Live macOS Keychain, Android/iOS system stores, vendor APIs, immutable firmware and
browser built-in roots need separate integrations. See each adapter's prerequisites
and limits before selecting it.

## Quick start

### 1. Install on your Linux controller

You need Python 3.12+ and [uv](https://docs.astral.sh/uv/). Install OpenSSH for remote
targets. Some adapters also need native tools, listed in the
[adapter reference](docs/adapters.md).

```bash
git clone https://github.com/AndriGitDev/emudhra-remover.git
cd emudhra-remover
uv sync --frozen
```

### 2. Configure a store

Create `inventory.json` with the stores you administer. This minimal example audits
a local application-owned PEM bundle; replace the path with its actual canonical
path before starting the server:

```json
{
  "targets": [
    {
      "id": "my-app",
      "transport": "local",
      "adapter": "pem-bundle",
      "path": "/absolute/path/to/roots.pem"
    }
  ]
}
```

For remote devices, start with [the SSH inventory example](examples/inventory.json)
or an [adapter-specific example](docs/adapters.md). Linux targets need `python3`;
Windows targets need `python` and OpenSSH Server. Independently verify host keys and
enroll them in `known_hosts`. The server uses default SSH keys or your existing SSH
agent; it ignores `~/.ssh/config`, aliases and ProxyCommand.

Inventory is loaded at startup and cannot be expanded through MCP. Ordinary store
paths must be canonical regular files; symlinked stores are rejected.

### 3. Connect your MCP client

Add this entry to your client's MCP configuration, replacing the absolute paths.
Use the absolute path to `uv` as `command` if your client cannot find it on PATH.

```json
{
  "mcpServers": {
    "emudhra-remover": {
      "command": "uv",
      "args": ["run", "--frozen", "--directory", "/absolute/path/to/emudhra-remover", "emudhra-remover"],
      "env": {
        "EMUDHRA_INVENTORY": "/absolute/path/to/inventory.json",
        "EMUDHRA_STATE_DIR": "/absolute/path/to/private-state",
        "EMUDHRA_ENABLE_WRITES": "0"
      }
    }
  }
}
```

The same configuration is available in [examples/mcp.json](examples/mcp.json).
The server uses stdio and exposes no public HTTP endpoint. It creates its private
state directory with mode `0700`; keep one server process per state directory and
retain it for recovery.

### 4. Ask your agent to audit

> List my configured targets and scan them against the bundled incident policy.
> Show affected certificates, verification findings and coverage limits. Prepare
> plans for targets that can be remediated, and wait for me to review them.

Scanning leaves targets unchanged. Planning saves recovery data locally without
changing the target. Review both `matches` and `verification`: an empty match list
alone does not establish that the store is consistent or the device is protected.

To apply a reviewed plan, set `EMUDHRA_ENABLE_WRITES=1` and restart the server with
the **same inventory and state directory**. Configure your client's approval controls
for apply, resume and rollback. Fresh apply plans expire after 15 minutes; create a
new plan if needed. Rollback does not expire, and restores prior trust.

See [operations and recovery](docs/operations.md) for tool arguments, environment
settings and interrupted-operation handling.

## Incident policy and scope

The bundled policy pins **23 certificate fingerprints** from Microsoft's October 26,
2026 announcement: 16 intermediates and seven trust-list removals.
[View the pinned announcement](https://github.com/TrustedRootProgram/Program-Requirements/blob/0fc6bfef5a36c073db756748e945b334bc87ba1f/Announcements.md)
and the [bundled manifest](src/emudhra_remover/incident.json).

The trust-list removals represent a broader distrust decision; they are not all
compromised private keys. One entry belongs to the Sectigo AAA hierarchy. Matching
uses exact certificate DER SHA-256, rather than issuer names or public-key hashes.
The policy is shipped with the server and cannot change through a live network feed.

Read [Microsoft's response](https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys)
when choosing your remediation policy. This server covers configured stores and
declared outputs. It does not find every alternate certificate sharing a compromised
key, implement revocation checking, or certify an entire device. OS and browser
vendor updates remain necessary.

## Validation and limits

Development and CI use synthetic certificates, temporary files and isolated native
stores. No real device trust stores were changed during development. Tests cover
conflicts, survivor preservation, interrupted writes, recovery and native format
interoperability. See [contributing](CONTRIBUTING.md#native-test-coverage) for the
platform workflows and how to reproduce their checks.

Important limits remain: native Windows chain enforcement, live macOS trust changes,
SELinux enforcement and mobile/firmware deployment are unvalidated. OpenSSL auxiliary
rejection has [purpose-specific exceptions](docs/adapters.md#openssl-trusted-pem).
Store verification establishes the adapter's declared result; check application
behavior separately after reload.

## License

[MIT](LICENSE). Independent of eMudhra, Microsoft and MCP client vendors.
