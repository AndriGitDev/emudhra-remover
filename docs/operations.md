# Operations and recovery

[README](../README.md) · [Adapter reference](adapters.md) · [Security](../SECURITY.md)

Start with the [README quick start](../README.md#quick-start). This guide describes
the tools exposed to an MCP client, how plans behave, and how to recover after an
interruption. Adapter-specific prerequisites still apply.

## Server configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `EMUDHRA_INVENTORY` | `inventory.json` in the process working directory | Operator-maintained target inventory |
| `EMUDHRA_STATE_DIR` | `~/.local/state/emudhra-remover` | Private SQLite journal and durable recovery snapshots |
| `EMUDHRA_ENABLE_WRITES` | Disabled unless exactly `1` | Enables apply, resume and rollback |
| `EMUDHRA_JAVA` | `java` on PATH | Controller JDK executable for Java adapters |
| `EMUDHRA_CERTUTIL` | `certutil` on PATH | Controller Mozilla NSS utility |
| `EMUDHRA_TRUST` | Automatic discovery | Controller p11-kit `trust` executable |
| `EMUDHRA_P11_MODULE` | Automatic discovery | Controller p11-kit trust module |

Use absolute inventory and state paths in client configuration. Java and BKS targets
also require `password_env`: the **name** of an environment variable holding the
store password. Supply its value through your client environment or secret manager;
do not put passwords in tool arguments or inventory files. p11-kit target runtime
paths belong in the inventory's `p11` options, separately from controller settings.

For a client or process supervisor that accepts a shell invocation:

```bash
EMUDHRA_INVENTORY="$PWD/inventory.json" \
EMUDHRA_STATE_DIR="$HOME/.local/state/emudhra-remover" \
EMUDHRA_ENABLE_WRITES=0 \
uv run --frozen emudhra-remover
```

This process speaks MCP over stdin/stdout; it is not an interactive shell or HTTP
service. Client configuration is usually the easiest way to launch it.

## Inventory and permissions

Each inventory entry identifies one target store. Use a unique `id`, an adapter,
and its store `path`. `transport` defaults to `ssh`; set it explicitly to `local`
for a local file. SSH targets also require `host` and `user`; `port` defaults to 22.
The adapter defaults to `pem-bundle`. See the [example index](adapters.md) for native
store paths, password environment names and required role/offline assertions.

Only configured targets are accessible through MCP. Changes to inventory require
a server restart. A saved plan is bound to its target configuration; changing that
configuration prevents apply or recovery until the original configuration is restored.

The server inherits the local account's permissions. SSH uses an existing account,
strict known-host checks, default keys or an existing agent, with no agent forwarding.
Custom SSH configuration and ProxyCommand are ignored. Linux SSH targets can use
`sudo: true` to run the fixed helper with `sudo -n`; granting passwordless Python
execution is equivalent to granting root shell access. Read the
[security model](../SECURITY.md) before choosing that option.

## MCP tools

| Tool | Arguments | Result or effect |
| --- | --- | --- |
| `list_adapters` | None | Implemented adapters, operations and validation coverage |
| `list_targets` | None | Configured target IDs and store settings |
| `scan_target` | `target_id` | Matches, store/snapshot hash, verification and coverage |
| `plan_removal` | `target_id` | Saves a plan and original state; leaves target unchanged |
| `inspect_plan` | `plan_id` | Saved status, observed target state and verification |
| `apply_plan` | `plan_id` | Applies an unexpired plan, checks conflicts and verifies result |
| `resume_plan` | `plan_id` | Finishes an interrupted NSS, p11-kit or Windows apply |
| `rollback_plan` | `plan_id` | Restores prior state within the adapter's recovery rules |

Despite the name `plan_removal`, distrust adapters retain or add denial records.
The `incident://emudhra/2026-10` MCP resource exposes the pinned policy and provenance.

## Review and apply

1. Scan the target. Read `coverage` and `verification` alongside `matches`. An adapter
   may omit already denied certificates from pending changes. Unmanaged anchors or
   stale outputs can require separate action even when no ordinary matches appear.
2. Create a plan. Review its affected certificates, target, before/after hashes and
   policy ID. `no-matches` returns no plan. Entries marked `removable: false` block
   planning; deletion adapters also refuse to empty a store.
3. Arrange the adapter's maintenance window. Stop other trust-store writers and keep
   NSS consumers closed. No adapter restarts applications or package managers.
4. Enable writes and restart with the same inventory and state directory. Apply a
   reviewed plan within 15 minutes of its creation. An applied plan cannot be replayed.
5. Inspect the result, reload consuming applications as appropriate, and test their
   behavior. Re-audit after package updates or native store regeneration.

The write gate permits mutations; it does not establish human approval. Your MCP
client must enforce approval for `apply_plan`, `resume_plan` and `rollback_plan`.

## Recover after an interruption

A lost connection can occur after a write. Call `inspect_plan` before taking another
action. Its `status` is the journal's operation status; `observed_state` describes
what the target currently contains. Check the separate `verification` result too:
a restored source configuration can coexist with incomplete generated outputs.

| Observed state | Meaning |
| --- | --- |
| `original` | The observed snapshot matches the original state; derived-output verification still matters |
| `modified` | The observed snapshot matches the planned state; derived-output verification still matters |
| `partially-modified` | NSS or Windows contains a recognized mixture of planned and original state |
| `conflict` | The snapshot differs from both saved states; adapter-specific recovery checks decide whether it is a known interrupted state |

Windows recovery can preserve drift in its read-only source store while checking
Disallowed independently; `read_only_source_changed` reports that drift. p11-kit
checks generated outputs separately and accepts only known generations during recovery.
See the [adapter reference](adapters.md) for the exact boundaries.

For an interrupted apply, `resume_plan` can complete saved NSS, p11-kit or Windows
changes when the adapter revision still matches. Other adapters use rollback for
recovery. `rollback_plan` restores prior trust and should be a deliberate decision.
Resume and rollback do not have the fresh-apply expiry, but neither bypasses
conflict detection. An interrupted rollback can be retried through `rollback_plan`.

A confirmed rejection before writing is recorded as `apply-failed`; it cannot be
rolled back. Resolve the cause and create a fresh plan. `apply-uncertain` and
`rollback-uncertain` mean recovery may be needed. Never treat killing SSH as proof
that its remote helper stopped.

Ordinary file rollback restores saved bytes. Debian and p11-kit regenerate derived
outputs from restored source policy, so native comments or timestamps can differ.
NSS restores its database pair; Windows removes only this plan's exact added denials.
The full multi-file/native operation is not atomic. Conflicting outside edits are
not silently overwritten.

## Preserve recovery data

The private journal directory must have mode `0700`; its SQLite database uses
`0600`. If you create the directory yourself, set its permissions explicitly.
Run one server per state directory and keep it on a local filesystem with reliable
locking and fsync. Back it up securely. Losing it loses the saved rollback data;
there is no automatic backup expiry or pruning.

File helpers retain a private `<store-path>.emudhra-work` sibling directory for
locking and crash-isolated temporary files. Leave it out of custom recursive CA
loaders. Standard nonrecursive loaders skip directories. The next write cleans up
abandoned temporary files under the lock; do not delete recovery state to bypass a
busy or conflict error.

## Common issues

| Symptom | What to check |
| --- | --- |
| Client cannot start the server | Absolute paths, Python 3.12+, and whether the client can find `uv` |
| SSH authentication or host-key failure | The actual host/user/port, independently verified `known_hosts`, and default keys or agent; shell aliases/config are not used |
| Writes disabled | Set `EMUDHRA_ENABLE_WRITES=1` in the server's client configuration and restart |
| Plan expired or adapter behavior changed | Create and review a fresh plan; old recoverable plans retain their rollback path |
| Busy store or NSS sidecars/profile locks | Close consumers and other writers; the tool will not delete profile locks or repair a live database |
| Verification failed or an entry is non-removable | Inspect the reported sources and the adapter's format/scope restrictions before attempting another plan |
| Inventory changed since planning | Restore the saved target configuration before recovery; do not repoint a plan to another store |

See [SECURITY.md](../SECURITY.md) for concurrency limits, untrusted target data and
native-platform security assumptions.
