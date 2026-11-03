import asyncio
import json
import time

from .adapters import get_adapter, transform_store
from .certificates import digest, policy
from .config import Inventory, Target
from .state import State
from .transport import Transport, WriteRejected


class Service:
    def __init__(self, inventory: Inventory, state: State, write_enabled: bool = False):
        self.inventory = inventory
        self.state = state
        self.write_enabled = write_enabled
        self.transport = Transport()
        self.incident = policy()
        self.locks = {target.id: asyncio.Lock() for target in inventory.targets}

    def list_targets(self) -> list[dict]:
        return [target.model_dump() for target in self.inventory.targets]

    async def scan(self, target_id: str) -> dict:
        target = self.inventory.target(target_id)
        data = await self.transport.read(target)
        try:
            verification = await self.transport.verify(target, require=False)
        except ValueError as error:
            verification = {"verified": False, "error": str(error)}
        matches, _after, count = await asyncio.to_thread(
            transform_store, target, data, self.incident
        )
        entries = {entry["sha256"].lower(): entry for entry in self.incident["certificates"]}
        for extra in verification.get("extra_anchors", []):
            entry = entries.get(extra["sha256"])
            if entry:
                matches.append(
                    {
                        **entry,
                        "source": extra["source"],
                        "removable": False,
                        "reason": "Unmanaged CApath anchor",
                    }
                )
        return {
            "verification": verification,
            "target_id": target_id,
            "store": target.path,
            "sha256": digest(data),
            "certificates_scanned": count,
            "matches": matches,
            "policy_id": self.incident["id"],
            "adapter": target.adapter,
            "coverage": get_adapter(target.adapter).coverage,
        }

    async def plan(self, target_id: str) -> dict:
        target = self.inventory.target(target_id)
        async with self.locks[target_id]:
            before = await self.transport.read(target)
            await self.transport.verify(target)
            matches, after, count = await asyncio.to_thread(
                transform_store, target, before, self.incident
            )
            if not matches:
                return {"target_id": target_id, "status": "no-matches", "plan_id": None}
            if any(entry.get("removable") is False for entry in matches):
                raise ValueError(
                    "Matching local anchors need separate removal; inspect scan results"
                )
            if get_adapter(target.adapter).removes_entries and len(matches) == count:
                raise ValueError("Refusing to empty the trust store; see scan_target for matches")
            report = {
                "target_id": target_id,
                "matches": matches,
                "certificates_scanned": count,
                "before_sha256": digest(before),
                "after_sha256": digest(after),
                "policy_id": self.incident["id"],
                "adapter_revision": get_adapter(target.adapter).revision,
            }
            plan_id = self.state.save(target.model_dump(), before, after, report)
            return {
                **report,
                "plan_id": plan_id,
                "status": "planned",
                "expires_in_seconds": 900,
                "warning": "Review affected services. Package updates may regenerate this bundle.",
            }

    def _target_for_plan(self, plan: dict):
        snapshot = json.loads(plan["target"])
        target = self.inventory.target(snapshot["id"])
        # Additive inventory fields must not invalidate older durable backups.
        # Normalize their defaults while retaining all explicit saved values.
        if target.model_dump() != Target.model_validate(snapshot).model_dump():
            raise ValueError(
                "Inventory changed since planning; restore the original target configuration"
            )
        return target

    async def status(self, plan_id: str) -> dict:
        plan = self.state.get(plan_id)
        target = self._target_for_plan(plan)
        current_data = await self.transport.read(target)
        current = digest(current_data)
        before, after = digest(plan["before"]), digest(plan["after"])
        observed = (
            "original" if current == before else ("modified" if current == after else "conflict")
        )
        try:
            verification = await self.transport.verify(target, require=False)
        except ValueError as error:
            verification = {"verified": False, "error": str(error)}
        if target.adapter == "nss-sql" and observed == "conflict":
            original_pair, modified_pair, pair = (
                json.loads(data) for data in (plan["before"], plan["after"], current_data)
            )
            if all(pair[key] in (original_pair[key], modified_pair[key]) for key in pair):
                observed = "partially-modified"
                verification = {"verified": False, "error": "Interrupted NSS database pair update"}
        return {
            "plan_id": plan_id,
            "status": plan["status"],
            "error": plan["error"],
            "report": json.loads(plan["report"]),
            "current_sha256": current,
            "verification": verification,
            "observed_state": observed,
        }

    async def apply(self, plan_id: str) -> dict:
        if not self.write_enabled:
            raise ValueError("Writes disabled: operator must set EMUDHRA_ENABLE_WRITES=1")
        plan = self.state.get(plan_id)
        target = self._target_for_plan(plan)
        if (
            json.loads(plan["report"]).get("adapter_revision", 1)
            != get_adapter(target.adapter).revision
        ):
            raise ValueError("Adapter behavior changed since planning; create a new plan")
        async with self.locks[target.id]:
            if time.time() - plan["created"] > 900:
                raise ValueError("Plan expired; create a new plan")
            self.state.claim(plan_id, "applying", ("planned",))
            try:
                await self.transport.replace(target, digest(plan["before"]), plan["after"])
                await self.transport.verify(target)
                if await self.transport.read(target) != plan["after"]:
                    raise ValueError("Post-apply verification failed")
            except WriteRejected as error:
                self.state.finish(plan_id, "apply-failed", str(error))
                raise
            except BaseException as error:
                # A disconnect can occur after rename. Keep a recoverable uncertain
                # state and let status compare actual bytes before the next action.
                self.state.finish(plan_id, "apply-uncertain", str(error))
                raise
            self.state.finish(plan_id, "applied")
            return {"plan_id": plan_id, "status": "applied", "sha256": digest(plan["after"])}

    async def resume(self, plan_id: str) -> dict:
        """Finish an interrupted native operation using only its durable snapshots."""
        if not self.write_enabled:
            raise ValueError("Writes disabled: operator must set EMUDHRA_ENABLE_WRITES=1")
        plan = self.state.get(plan_id)
        target = self._target_for_plan(plan)
        if target.adapter not in ("nss-sql", "p11-kit"):
            raise ValueError("Roll-forward recovery is supported for NSS and p11-kit")
        if (
            json.loads(plan["report"]).get("adapter_revision", 1)
            != get_adapter(target.adapter).revision
        ):
            raise ValueError("Adapter behavior changed; this plan can only be rolled back")
        async with self.locks[target.id]:
            self.state.claim(plan_id, "applying", ("apply-uncertain", "applying"))
            try:
                current = await self.transport.read(target)
                if current != plan["after"]:
                    recovery = (
                        {"recovery_from": plan["before"]} if target.adapter == "nss-sql" else {}
                    )
                    await self.transport.replace(
                        target, digest(plan["before"]), plan["after"], **recovery
                    )
                if target.adapter == "p11-kit":
                    await self.transport.reconcile(
                        target, digest(plan["after"]), recovery_from=plan["before"]
                    )
                await self.transport.verify(target)
                if await self.transport.read(target) != plan["after"]:
                    raise ValueError("Post-resume verification failed")
            except BaseException as error:
                self.state.finish(plan_id, "apply-uncertain", str(error))
                raise
            self.state.finish(plan_id, "applied")
            return {"plan_id": plan_id, "status": "applied", "sha256": digest(plan["after"])}

    async def rollback(self, plan_id: str) -> dict:
        if not self.write_enabled:
            raise ValueError("Writes disabled: operator must set EMUDHRA_ENABLE_WRITES=1")
        plan = self.state.get(plan_id)
        target = self._target_for_plan(plan)
        async with self.locks[target.id]:
            self.state.claim(
                plan_id,
                "rolling-back",
                ("applied", "apply-uncertain", "rollback-uncertain", "applying", "rolling-back"),
            )
            try:
                current = await self.transport.read(target)
                if current != plan["before"]:
                    recovery = (
                        {"recovery_from": plan["after"]} if target.adapter == "nss-sql" else {}
                    )
                    await self.transport.replace(
                        target, digest(plan["after"]), plan["before"], **recovery
                    )
                else:
                    recovery = (
                        {"recovery_from": plan["after"]} if target.adapter == "p11-kit" else {}
                    )
                    await self.transport.reconcile(target, digest(plan["before"]), **recovery)
                await self.transport.verify(target)
                if await self.transport.read(target) != plan["before"]:
                    raise ValueError("Post-rollback verification failed")
            except BaseException as error:
                self.state.finish(plan_id, "rollback-uncertain", str(error))
                raise
            self.state.finish(plan_id, "rolled-back")
            return {"plan_id": plan_id, "status": "rolled-back"}
