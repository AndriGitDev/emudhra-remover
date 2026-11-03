# eMudhra Remover MCP

An MCP server that lets your agent audit configured devices and remove specific
incident-listed CA certificates from their PEM trust bundles. It uses exact SHA-256
fingerprints, saved removal plans, durable backups, atomic writes and verified rollback.
It works with any MCP client supporting the stdio transport. No model API key is needed.

**v0.1 supports local Linux and SSH-accessible Linux devices with ordinary PEM bundles.**
It is an initial implementation, not a universal device updater. No real device has
been changed during development; testing uses temporary stores and synthetic certificates.

## Incident policy

The bundled policy is a reviewed snapshot of Microsoft's October 26, 2026 announcement:
[official announcement and fingerprints](https://github.com/TrustedRootProgram/Program-Requirements/blob/0fc6bfef5a36c073db756748e945b334bc87ba1f/Announcements.md).
It contains 16 intermediate certificate fingerprints and seven trust-list removals.
The root/trust-list entries are a broader distrust decision; they are not all
compromised private keys. One entry belongs to the Sectigo AAA hierarchy, so the
policy's scope is broader than an issuer-name search for eMudhra.

Read [Microsoft's response](https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys)
before choosing a remediation policy. This tool removes matching certificates from
the configured bundle only. It does not install an SPKI denylist, implement revocation
checking, find every alternate certificate using a compromised key, or prove that
every application on the device is protected. Updates from OS/browser vendors remain
necessary. No network feed can silently change the bundled removal policy.

## Quick start

Install [uv](https://docs.astral.sh/uv/), Python 3.12+, and OpenSSH on your Linux controller.
Remote targets require Python 3 and an existing SSH account. Devices without Python,
SSH, or an editable PEM bundle are currently unsupported.

```bash
git clone https://github.com/AndriGitDev/emudhra-remover.git
cd emudhra-remover
uv sync --frozen
cp examples/inventory.json inventory.json
# Edit inventory.json to include only your own devices and actual bundle paths.
```

For a local store use `{"id":"app","transport":"local","path":"/absolute/path/roots.pem"}`.
Use the real canonical path; symlinked trust stores are rejected. Targets use the
`pem-bundle` adapter by default. Inventory is loaded at startup and cannot be edited
through MCP. Remote SSH uses default keys or an existing SSH agent; custom aliases,
ProxyCommand and ~/.ssh/config are intentionally ignored. Enroll and independently
verify each host's key in `known_hosts` before connecting.

Copy [examples/mcp.json](examples/mcp.json) into your client's MCP configuration,
replacing all absolute paths. Keep `EMUDHRA_ENABLE_WRITES` at `0` for the initial audit.
The private state directory is created with mode 0700. If you create it yourself,
set that mode explicitly. Keep one server process per state directory.

An equivalent server invocation is:

```bash
EMUDHRA_INVENTORY="$PWD/inventory.json" \
EMUDHRA_STATE_DIR="$HOME/.local/state/emudhra-remover" \
EMUDHRA_ENABLE_WRITES=0 \
uv run --frozen emudhra-remover
```

This is a stdio server: start it through an MCP client. It does not expose a public
HTTP endpoint. See [SECURITY.md](SECURITY.md) for permissions and recovery behavior.

## Agent workflow

Try: “List my configured devices, scan each trust bundle for the eMudhra incident
policy, and show me removal plans with the affected certificates and store hashes.”

| Tool | Behavior |
| --- | --- |
| `list_targets` | List configured devices and store paths |
| `scan_target` | Read one store and report exact matches |
| `plan_removal` | Save original bytes and a plan; leave the target unchanged |
| `inspect_plan` | Report saved status and compare current bytes to the plan |
| `apply_plan` | Apply an unexpired plan and verify written bytes |
| `rollback_plan` | Restore original bytes if no conflicting change occurred |

The `incident://emudhra/2026-10` MCP resource exposes the full policy and provenance.

To allow remediation, set `EMUDHRA_ENABLE_WRITES=1` in your client configuration and
restart the server. Review the plan and service dependencies, then authorize your
client to invoke `apply_plan`. Plans expire after 15 minutes and cannot be replayed.
The write setting allows both apply and rollback; it does not prove user approval.
Configure your MCP client's approval controls for those tools.

After a connection failure, use `inspect_plan`. `original` means the store equals
the backup; `modified` means it equals the planned replacement; `conflict` means
someone else changed it. A saved uncertain/interrupted plan can be rolled back,
including after a server restart. Rollback does not expire and restores the removed
trust. Conflicting edits are never overwritten. Preserve the state directory.
Confirmed pre-write rejections are recorded as `apply-failed` and cannot invoke
rollback. A private `<bundle-path>.emudhra-work` directory holds the target lock
and crash-isolated temporary files; exclude it from custom recursive CA loaders.

## Device and trust-store coverage

| Surface | v0.1 |
| --- | --- |
| Application-owned PEM file on Linux | Audit, plan, remove, verify, rollback |
| Linux appliance/media player over SSH with Python 3 | Same, if its trust store is an editable PEM file |
| Generated Linux system CA bundle | File operation only; regeneration can restore removed CAs |
| Debian/Fedora persistent OS distrust configuration | Planned native adapters |
| Windows Certificate Store / Disallowed store | Planned native adapter |
| macOS Keychain / trust settings | Planned native adapter |
| Android, iOS, vendor APIs, immutable firmware | Vendor-specific adapter or firmware update required |
| Firefox NSS, Java JKS/PKCS#12, containers, browser-managed stores | Separate adapters/stores required |

Removing a certificate from a generated file such as
`/etc/ssl/certs/ca-certificates.crt` is **not persistent OS distrust**. Prefer vendor
updates or native OS mechanisms. This server does not run `update-ca-certificates`,
`update-ca-trust`, restart applications, or change package-managed source anchors.
Reaudit after package updates, store regeneration and application restarts. Never
interpret “no matches” as complete device compliance.

## Development

```bash
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv build
```

Tests exercise the actual local helper, temporary files, process-death recovery,
mode/owner/group/xattr/ACL preservation, optimistic concurrency, input validation, and MCP tools over
both in-memory and real stdio connections. SSH command construction is tested without
connecting to a live device. CI runs on Linux with Python 3.12 and 3.13.

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

Future adapters should retain the same flow: explicit inventory, inspect, persist
backup, bind a plan to current state, apply a narrow change, verify, and recover.
Native OS adapters must make persistent distrust changes rather than editing their
generated bundles. Contributions should include realistic platform fixtures.

## License

MIT. The project is independent of eMudhra, Microsoft, and MCP client vendors.
