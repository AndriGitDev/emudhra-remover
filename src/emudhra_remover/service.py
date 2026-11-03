import asyncio
import json
import time

from .certificates import digest, filter_bundle, policy
from .config import Inventory
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
        matches, _after, count = filter_bundle(data, self.incident)
        return {
            "target_id": target_id,
            "store": target.path,
            "sha256": digest(data),
            "certificates_scanned": count,
            "matches": matches,
            "policy_id": self.incident["id"],
            "coverage": "configured-pem-bundle-only",
        }

    async def plan(self, target_id: str) -> dict:
        target = self.inventory.target(target_id)
        async with self.locks[target_id]:
            before = await self.transport.read(target)
            matches, after, count = filter_bundle(before, self.incident)
            if not matches:
                return {"target_id": target_id, "status": "no-matches", "plan_id": None}
            if len(matches) == count:
                raise ValueError("Refusing to empty the trust store; see scan_target for matches")
            report = {
                "target_id": target_id,
                "matches": matches,
                "certificates_scanned": count,
                "before_sha256": digest(before),
                "after_sha256": digest(after),
                "policy_id": self.incident["id"],
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
        if target.model_dump() != snapshot:
            raise ValueError(
                "Inventory changed since planning; restore the original target configuration"
            )
        return target

    async def status(self, plan_id: str) -> dict:
        plan = self.state.get(plan_id)
        target = self._target_for_plan(plan)
        current = digest(await self.transport.read(target))
        before, after = digest(plan["before"]), digest(plan["after"])
        return {
            "plan_id": plan_id,
            "status": plan["status"],
            "error": plan["error"],
            "report": json.loads(plan["report"]),
            "current_sha256": current,
            "observed_state": "original"
            if current == before
            else ("modified" if current == after else "conflict"),
        }

    async def apply(self, plan_id: str) -> dict:
        if not self.write_enabled:
            raise ValueError("Writes disabled: operator must set EMUDHRA_ENABLE_WRITES=1")
        plan = self.state.get(plan_id)
        target = self._target_for_plan(plan)
        async with self.locks[target.id]:
            if time.time() - plan["created"] > 900:
                raise ValueError("Plan expired; create a new plan")
            self.state.claim(plan_id, "applying", ("planned",))
            try:
                await self.transport.replace(target, digest(plan["before"]), plan["after"])
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
                    await self.transport.replace(target, digest(plan["after"]), plan["before"])
                if await self.transport.read(target) != plan["before"]:
                    raise ValueError("Post-rollback verification failed")
            except BaseException as error:
                self.state.finish(plan_id, "rollback-uncertain", str(error))
                raise
            self.state.finish(plan_id, "rolled-back")
            return {"plan_id": plan_id, "status": "rolled-back"}
