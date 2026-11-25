"""授权感知、可续读、可撤回的告警转发核心。

该模块只依赖 Python 标准库。HTTP 层、命令行和场景回放都调用这里的同一组
接口，避免出现“实时通道一套规则、重连/恢复通道另一套规则”。
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "Service",
    "GatewayError",
    "NotFoundError",
    "InvalidCursorError",
    "ConflictError",
    "alarm_key",
]


class GatewayError(Exception):
    """可向调用方展示的业务错误。"""

    code = "gateway_error"
    http_status = 400

    def __init__(self, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_payload(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            },
        }


class NotFoundError(GatewayError):
    code = "not_found"
    http_status = 404


class InvalidCursorError(GatewayError):
    code = "invalid_cursor"
    http_status = 409

    def __init__(self, message: str, *, reason: str = "cursor_expired"):
        super().__init__(message, details={"rebuild_required": True, "reason": reason})
        self.reason = reason


class ConflictError(GatewayError):
    code = "conflict"
    http_status = 409


def alarm_key(site: str, alarm: str | int) -> str:
    """告警身份是“首次发布厂区 + 告警号”，不含设备。"""

    return f"{site}\x1f{alarm}"


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def _fresh_state() -> dict[str, Any]:
    return {
        "version": 1,
        "op_seq": 0,
        "clock": -1,
        "trim_retain_from": None,
        "events": [],
        "alarms": {},
        "devices": {},
        "grants": [],
        "gaps": [],
        "subscriptions": {},
        "client_index": {},
        "cursor_index": {},
        "deliveries": {},
    }


class Service:
    """所有授权、发布、订阅、确认和留存操作的事务入口。"""

    def __init__(self, state_path: str | os.PathLike[str] | None = None):
        self.state_path = Path(state_path) if state_path else None
        self.lock = threading.RLock()
        # 条件变量与 RLock 共用；SSE 长连接据此等待授权/事件变化。
        self.changed = threading.Condition(self.lock)
        if self.state_path and self.state_path.exists():
            self.state = json.loads(self.state_path.read_text(encoding="utf-8"))
            self._migrate_state()
        else:
            self.state = _fresh_state()
        # 进程/HTTP 连接不跨重启存活。逻辑连接由 open 重新建立。
        with self.lock:
            for sub in self.state.get("subscriptions", {}).values():
                sub["connected"] = False
            self._reevaluate_all(reason="service_start")
            self._save_locked()

    # ------------------------------------------------------------------
    # 持久化与基础工具
    # ------------------------------------------------------------------
    def _migrate_state(self) -> None:
        base = _fresh_state()
        for key, value in base.items():
            self.state.setdefault(key, value)

    def _save_locked(self) -> None:
        if self.state_path is not None:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_name(self.state_path.name + ".tmp")
            temporary.write_text(
                json.dumps(self.state, ensure_ascii=False, sort_keys=False, indent=2),
                encoding="utf-8",
            )
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, self.state_path)
        self.changed.notify_all()

    def save(self) -> None:
        with self.lock:
            self._save_locked()

    def wait_for_change(self, last_seq: int | None, timeout: float = 15.0) -> int:
        """等待 op_seq 变化；返回当前 op_seq，供长连接避免丢通知。"""

        with self.lock:
            current = int(self.state["op_seq"])
            if last_seq is not None and current == last_seq:
                self.changed.wait(timeout=timeout)
            return int(self.state["op_seq"])

    @staticmethod
    def _now(at: float | int | None) -> float | int:
        return int(time.time()) if at is None else at

    def _tick(self, at: float | int | None) -> tuple[int, float | int]:
        """分配全局操作序号；相同逻辑秒点的顺序由调用次序决定。"""

        ts = self._now(at)
        self.state["op_seq"] += 1
        self.state["clock"] = max(self.state.get("clock", -1), ts)
        return self.state["op_seq"], ts

    def _event_by_id(self, event_id: str) -> dict[str, Any] | None:
        for event in self.state["events"]:
            if event["id"] == event_id:
                return event
        return None

    def _copy(self, value: Any) -> Any:
        return copy.deepcopy(value)

    # ------------------------------------------------------------------
    # 授权范围判断
    # ------------------------------------------------------------------
    def _active_grant(
        self, principal: str, site: str, device: str
    ) -> dict[str, Any] | None:
        found = None
        for grant in self.state["grants"]:
            if (
                grant["principal"] == principal
                and grant["site"] == site
                and grant["device"] == device
                and grant.get("end_seq") is None
            ):
                found = grant
        return found

    def _current_device_site(self, device: str, fallback_site: str) -> str:
        record = self.state["devices"].get(device)
        return str(record["site"]) if record else str(fallback_site)

    def _in_unauthorized_gap(
        self, principal: str, site: str, device: str, event_seq: int
    ) -> bool:
        for gap in self.state["gaps"]:
            if (
                gap["principal"] == principal
                and gap["site"] == site
                and gap["device"] == device
                and gap["start_seq"] < event_seq
                and (gap.get("end_seq") is None or event_seq < gap["end_seq"])
            ):
                return True
        return False

    def _visible_now(self, principal: str, event: dict[str, Any]) -> bool:
        """按当前设备归属和当前授权判断一条事件是否可新交付。

        告警身份保留首次发布厂区（见 alarm_key），但设备迁站后，授权匹配
        使用设备“当前所在厂区 + 设备号”。旧厂区授权不会自动转移成新厂区
        授权；若当前厂区另有有效授权且其 since/gap 规则允许，才可公开。
        """

        origin_site = event["site"]
        device = event["device"]
        current_site = self._current_device_site(device, origin_site)

        grant = self._active_grant(principal, current_site, device)
        if grant is None:
            return False
        if event["timestamp"] < grant["since_ts"]:
            return False
        if self._in_unauthorized_gap(
            principal, current_site, device, int(event["seq"])
        ):
            return False
        return True

    def _alarm_visible_now(
        self, principal: str, alarm: dict[str, Any]
    ) -> bool:
        event_like = {
            "site": alarm["site"],
            "device": alarm["device"],
            "seq": alarm.get("latest_seq", 0),
            "timestamp": alarm.get("latest_timestamp", 0),
        }
        return self._visible_now(principal, event_like)

    # ------------------------------------------------------------------
    # 授权维护接口
    # ------------------------------------------------------------------
    def allow(
        self,
        principal: str,
        site: str,
        device: str,
        since: float | int | None = None,
        at: float | int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        with self.lock:
            seq, ts = self._tick(at)
            since_ts = ts if since is None else since

            # 恢复同一范围：关闭失权区间。中间区间仍然留在 gaps 中，
            # 历史补发时会继续排除其中的事件。
            for gap in self.state["gaps"]:
                if (
                    gap.get("end_seq") is None
                    and gap["principal"] == principal
                    and gap["site"] == site
                    and gap["device"] == device
                ):
                    gap["end_seq"] = seq
                    gap["end_ts"] = ts

            # 同范围重复 allow 视为安装新的授权世代；不制造失权区间。
            for grant in self.state["grants"]:
                if (
                    grant.get("end_seq") is None
                    and grant["principal"] == principal
                    and grant["site"] == site
                    and grant["device"] == device
                ):
                    grant["end_seq"] = seq
                    grant["end_ts"] = ts

            grant = {
                "id": new_id("grant"),
                "principal": principal,
                "site": site,
                "device": device,
                "since_ts": since_ts,
                "start_seq": seq,
                "start_ts": ts,
                "end_seq": None,
                "end_ts": None,
            }
            self.state["grants"].append(grant)

            backfilled = self._backfill_after_grant(principal, site, device)
            self._save_locked()
            return {
                "ok": True,
                "grant": self._copy(grant),
                "backfilled_delivery_refs": backfilled,
            }

    def deny(
        self,
        principal: str,
        site: str,
        device: str,
        at: float | int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        with self.lock:
            seq, ts = self._tick(at)
            closed = []
            for grant in self.state["grants"]:
                if (
                    grant.get("end_seq") is None
                    and grant["principal"] == principal
                    and grant["site"] == site
                    and grant["device"] == device
                ):
                    grant["end_seq"] = seq
                    grant["end_ts"] = ts
                    closed.append(grant["id"])

            # 幂等：已有未关闭区间时不重复建。
            has_open_gap = any(
                gap.get("end_seq") is None
                and gap["principal"] == principal
                and gap["site"] == site
                and gap["device"] == device
                for gap in self.state["gaps"]
            )
            if not has_open_gap:
                self.state["gaps"].append(
                    {
                        "id": new_id("gap"),
                        "principal": principal,
                        "site": site,
                        "device": device,
                        "reason": "deny",
                        "start_seq": seq,
                        "start_ts": ts,
                        "end_seq": None,
                        "end_ts": None,
                    }
                )

            changes = self._reevaluate_principal_scope(
                principal, site, device, reason="authorization_revoked"
            )
            self._save_locked()
            return {
                "ok": True,
                "closed_grant_ids": closed,
                "revocations": changes["revocations"],
                "cancelled": changes["cancelled"],
            }

    def move_device(
        self,
        device: str,
        from_site: str,
        to_site: str,
        at: float | int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        with self.lock:
            seq, ts = self._tick(at)
            record = self.state["devices"].setdefault(
                device, {"site": from_site, "history": []}
            )
            old_site = record.get("site", from_site)
            record["history"].append(
                {
                    "from_site": old_site,
                    "to_site": to_site,
                    "seq": seq,
                    "timestamp": ts,
                }
            )
            record["site"] = to_site

            # 设备迁站会使所有携带该设备、但按当前归属已不可公开的交付
            # 立即进入取消/撤回流程。
            changes = self._reevaluate_all(device=device, reason="device_moved")
            self._save_locked()
            return {
                "ok": True,
                "device": device,
                "from_site": old_site,
                "to_site": to_site,
                "revocations": changes["revocations"],
                "cancelled": changes["cancelled"],
            }

    # ------------------------------------------------------------------
    # 事件发布接口
    # ------------------------------------------------------------------
    def publish(
        self,
        site: str,
        device: str,
        alarm: str | int,
        rev: int,
        status: str,
        body: str | None = None,
        at: float | int | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        with self.lock:
            if status not in {"raised", "corrected", "cancelled"}:
                raise GatewayError(f"未知告警状态: {status}")
            seq, ts = self._tick(at)
            event_id = f"evt_{seq}"
            event = {
                "id": event_id,
                "seq": seq,
                "timestamp": ts,
                "site": site,
                "device": device,
                "alarm": str(alarm),
                "rev": int(rev),
                "status": status,
                "body": body,
                "extra": extra,
            }
            self.state["events"].append(event)

            # 保留当前告警聚合状态；trim 只压缩原始事件前缀，不销毁
            # “当前授权范围重建”所需的可用状态。
            key = alarm_key(site, alarm)
            self.state["alarms"][key] = {
                "site": site,
                "device": device,
                "alarm": str(alarm),
                "rev": int(rev),
                "status": status,
                "body": body,
                "latest_event_id": event_id,
                "latest_seq": seq,
                "latest_timestamp": ts,
                "extra": extra,
            }
            self.state["devices"].setdefault(device, {"site": site, "history": []})

            created: list[str] = []
            for sub in self.state["subscriptions"].values():
                # last_event_seq 是服务端“已扫描/已过滤”水位；客户端可续读
                # 进度 progress_* 只在消息实际交付或重建确认后推进。
                sub["last_event_seq"] = seq
                if self._visible_now(sub["principal"], event):
                    delivery = self._create_event_delivery(sub, event)
                    created.append(delivery["id"])

            self._save_locked()
            return {
                "ok": True,
                "event_id": event_id,
                "seq": seq,
                "delivery_refs": created,
            }

    def trim(
        self,
        retain_from: float | int,
        at: float | int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        with self.lock:
            seq, ts = self._tick(at)
            self.state["trim_retain_from"] = retain_from
            before = len(self.state["events"])
            self.state["events"] = [
                event
                for event in self.state["events"]
                if event["timestamp"] >= retain_from
            ]
            deleted = before - len(self.state["events"])
            reset: list[str] = []
            for sub in self.state["subscriptions"].values():
                if self._evaluate_retention(sub):
                    reset.append(sub["id"])
            self._save_locked()
            return {
                "ok": True,
                "op_seq": seq,
                "op_ts": ts,
                "deleted_events": deleted,
                "reset_subscription_ids": reset,
            }

    # ------------------------------------------------------------------
    # 订阅、握手、拉取、确认
    # ------------------------------------------------------------------
    def open(
        self,
        principal: str,
        client: str,
        local_state: str = "resume",
        cursor: str | None = None,
        at: float | int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        with self.lock:
            seq, ts = self._tick(at)
            try:
                sub = self._resolve_subscription(
                    principal, client, cursor, create=True
                )
            except InvalidCursorError:
                # 重建本来就是放弃旧位点、按当前授权重开；未知/失效凭据不应
                # 阻止重建。普通 resume 仍把错误返回给浏览器。
                if local_state != "rebuild":
                    raise
                sub = self._resolve_subscription(
                    principal, client, None, create=True
                )
            assert sub is not None

            # 新握手接管旧逻辑连接；上次已发出但未确认的消息重新进入队列。
            self._recover_inflight(sub)
            sub["connected"] = True
            sub["last_open_mode"] = local_state
            sub["last_open_seq"] = seq
            sub["last_open_ts"] = ts

            if local_state == "rebuild":
                self._begin_rebuild(sub, seq, ts)
            else:
                self._evaluate_retention(sub)

            self._save_locked()
            return self.status(principal, client, include_messages=False)

    def disconnect(
        self,
        principal: str,
        client: str,
        at: float | int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        with self.lock:
            self._tick(at)
            sub = self._get_subscription(principal, client)
            if sub is None:
                raise NotFoundError("订阅不存在")
            sub["connected"] = False
            recovered = self._recover_inflight(sub)
            self._save_locked()
            return {
                "ok": True,
                "connected": False,
                "redelivered_refs": recovered,
            }

    def fetch(
        self,
        principal: str,
        client: str,
        limit: int | None = None,
        cursor: str | None = None,
        at: float | int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        with self.lock:
            seq, ts = self._tick(at)
            sub = self._resolve_subscription(principal, client, cursor, create=False)
            if sub is None:
                raise NotFoundError("订阅尚未 open")
            if cursor and cursor != sub["progress_token"]:
                raise InvalidCursorError("进度凭据不属于该订阅")

            # HTTP/进程重启后即使客户端未先 open 就 fetch，也按恢复处理，
            # 但所有消息仍走同一个可见性/撤回过滤器。
            if not sub.get("connected", False):
                self._recover_inflight(sub)
                sub["connected"] = True

            self._pump_new_events(sub)
            self._evaluate_retention(sub)

            state = sub.get("state", "active")
            messages: list[dict[str, Any]] = []
            normal_count = 0
            revocation_count = 0

            for delivery_id in list(sub["delivery_ids"]):
                delivery = self.state["deliveries"][delivery_id]
                if delivery.get("status") != "queued":
                    continue

                kind = delivery["kind"]
                if kind == "event":
                    if delivery.get("revoked") or delivery.get("cancelled"):
                        delivery["status"] = "cancelled"
                        continue
                    # 重建/重置确认前只放撤回和重建状态，不继续放普通流。
                    if state in {"reset_required", "rebuild_pending"}:
                        continue
                    if limit is not None and len(messages) >= limit:
                        continue
                    event = self._event_by_id(delivery["event_id"])
                    if event is None or not self._visible_now(principal, event):
                        self._invalidate_event_delivery(
                            sub, delivery, reason="visibility_rechecked"
                        )
                        continue
                    rendered = self._render_event_message(delivery, event)
                    messages.append(rendered)
                    delivery["status"] = "delivered"
                    delivery["ever_sent"] = True
                    delivery["last_sent_ts"] = ts
                    sub["progress_seq"] = max(
                        int(sub.get("progress_seq", 0)), int(event["seq"])
                    )
                    sub["progress_ts"] = max(
                        float(sub.get("progress_ts", event["timestamp"])),
                        float(event["timestamp"]),
                    )
                    normal_count += 1

                elif kind == "revocation":
                    if limit is not None and len(messages) >= limit:
                        continue
                    rendered = self._render_revocation_message(delivery)
                    messages.append(rendered)
                    delivery["status"] = "delivered"
                    delivery["ever_sent"] = True
                    delivery["last_sent_ts"] = ts
                    revocation_count += 1

            if state in {"reset_required", "rebuild_pending"}:
                # 重建确认前，即使撤回在上一批已发出但尚未显式 ack，随后的
                # fetch 仍应能看到它，避免浏览器把“已发过一次”误当成完成。
                present = {
                    message["delivery_ref"]
                    for message in messages
                    if message["kind"] == "revocation"
                }
                for delivery_id in sub["delivery_ids"]:
                    delivery = self.state["deliveries"][delivery_id]
                    if delivery.get("kind") != "revocation":
                        continue
                    if delivery.get("status") == "acked":
                        continue
                    rendered = self._render_revocation_message(delivery)
                    if rendered["delivery_ref"] not in present:
                        messages.append(rendered)
                        present.add(rendered["delivery_ref"])

            result = self.status(principal, client, include_messages=False)
            result.update(
                {
                    "ok": True,
                    # 内部长连接唤醒使用；HTTP/SSE 对外发送前会移除。
                    "_op_seq": seq,
                    "messages": messages,
                    "events": [m for m in messages if m["kind"] == "event"],
                    "revocations": [
                        m for m in messages if m["kind"] == "revocation"
                    ],
                    "delivered_count": len(messages),
                }
            )
            self._save_locked()
            return result

    def ack(
        self,
        principal: str,
        client: str,
        ref: str,
        at: float | int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        with self.lock:
            self._tick(at)
            sub = self._get_subscription(principal, client)
            if sub is None:
                raise NotFoundError("订阅不存在")
            delivery = self.state["deliveries"].get(ref)
            if delivery is None or delivery.get("sub_id") != sub["id"]:
                raise NotFoundError("交付标识不属于该客户端订阅")
            already = delivery.get("status") == "acked"
            delivery["status"] = "acked"
            delivery["acked_ts"] = self._now(at)
            if delivery["kind"] == "revocation":
                delivery["revocation_acked"] = True
            self._save_locked()
            return {
                "ok": True,
                "acked_ref": ref,
                "already_acked": already,
                "progress": sub["progress_token"],
            }

    def rebuild_ack(
        self,
        principal: str,
        client: str,
        rebuild_id: str | None = None,
        at: float | int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        with self.lock:
            seq, ts = self._tick(at)
            sub = self._get_subscription(principal, client)
            if sub is None:
                raise NotFoundError("订阅不存在")
            rebuild = sub.get("rebuild")
            if not rebuild:
                if rebuild_id is not None:
                    raise NotFoundError("没有待确认的重建")
                return {"ok": True, "rebuild_completed": False}
            if rebuild_id is not None and rebuild["id"] != rebuild_id:
                raise ConflictError("rebuild_id 与当前待确认重建不一致")

            rebuild["acked"] = True
            rebuild["acked_seq"] = seq
            rebuild["acked_ts"] = ts

            # 快照已经包含水位线之前的当前状态；这些普通交付无需再重放。
            # 撤回交付仍保留其自己的 ack 生命周期，不能被 rebuild_ack 冒名确认。
            watermark = int(rebuild.get("watermark_seq", 0))
            for delivery_id in sub["delivery_ids"]:
                delivery = self.state["deliveries"][delivery_id]
                if (
                    delivery["kind"] == "event"
                    and delivery.get("created_event_seq", 0) <= watermark
                    and delivery.get("status") in {"queued", "delivered"}
                    and not delivery.get("revoked")
                ):
                    delivery["status"] = "acked"
                    delivery["acked_via"] = "rebuild_ack"

            sub["state"] = "active"
            sub["progress_ts"] = ts
            sub["progress_seq"] = max(int(sub.get("progress_seq", 0)), watermark)
            sub["last_event_seq"] = max(int(sub.get("last_event_seq", 0)), watermark)
            self._save_locked()
            return {
                "ok": True,
                "rebuild_id": rebuild["id"],
                "rebuild_completed": True,
                "progress": sub["progress_token"],
            }

    # ------------------------------------------------------------------
    # 状态与浏览器运维台视图
    # ------------------------------------------------------------------
    def status(
        self,
        principal: str | None = None,
        client: str | None = None,
        *,
        include_messages: bool = False,
    ) -> dict[str, Any]:
        with self.lock:
            if principal is not None and client is not None:
                sub = self._get_subscription(principal, client)
                if sub is None:
                    raise NotFoundError("订阅不存在")
                return self._subscription_status(sub, include_messages)

            subscriptions = []
            for sub in self.state["subscriptions"].values():
                if principal is not None and sub["principal"] != principal:
                    continue
                if client is not None and sub["client"] != client:
                    continue
                subscriptions.append(
                    self._subscription_status(sub, include_messages=False)
                )
            return {
                "ok": True,
                "service": "alert-gateway",
                "trim_retain_from": self.state.get("trim_retain_from"),
                "subscriptions": subscriptions,
            }

    def list_subscriptions(self) -> dict[str, Any]:
        return self.status()

    def _subscription_status(
        self, sub: dict[str, Any], include_messages: bool
    ) -> dict[str, Any]:
        unacked_revocations: list[dict[str, Any]] = []
        evict_refs: list[str] = []
        unacked_events = 0
        for delivery_id in sub["delivery_ids"]:
            delivery = self.state["deliveries"][delivery_id]
            if delivery["kind"] == "revocation" and delivery.get("status") != "acked":
                rendered = self._render_revocation_message(delivery)
                unacked_revocations.append(rendered)
                evict_refs.append(delivery["revocation_for_id"])
            if (
                delivery["kind"] == "event"
                and delivery.get("status") not in {"acked", "cancelled"}
                and not delivery.get("revoked")
            ):
                unacked_events += 1

        rebuild = sub.get("rebuild")
        public_rebuild = (
            self._copy(rebuild) if rebuild and not rebuild.get("acked") else None
        )
        result = {
            "ok": True,
            "subscription_id": sub["id"],
            "principal": sub["principal"],
            "client": sub["client"],
            "connected": sub.get("connected", False),
            "state": sub.get("state", "active"),
            "reset_required": sub.get("state") == "reset_required",
            "rebuild_required": sub.get("state") == "reset_required",
            "reset_reason": sub.get("reset_reason"),
            # 随机不透明凭据；不编码偏移、设备或跳过数量。
            "progress": sub["progress_token"],
            "progress_token": sub["progress_token"],
            "cursor": sub["progress_token"],
            "progress_available": sub.get("state") == "active",
            "resumable": sub.get("state") == "active",
            "unacked_event_count": unacked_events,
            "evict_refs": self._copy(evict_refs),
            "cache_clear_refs": self._copy(evict_refs),
            "pending_evictions": self._copy(unacked_revocations),
            "rebuild": public_rebuild,
            "snapshot": public_rebuild.get("items") if public_rebuild else None,
        }
        if include_messages:
            result["messages"] = []
        return result

    # ------------------------------------------------------------------
    # 订阅内部辅助
    # ------------------------------------------------------------------
    def _client_key(self, principal: str, client: str) -> str:
        return f"{principal}\x1f{client}"

    def _get_subscription(
        self, principal: str, client: str
    ) -> dict[str, Any] | None:
        sub_id = self.state["client_index"].get(self._client_key(principal, client))
        if not sub_id:
            return None
        return self.state["subscriptions"].get(sub_id)

    def _resolve_subscription(
        self,
        principal: str,
        client: str,
        cursor: str | None,
        *,
        create: bool,
    ) -> dict[str, Any] | None:
        if cursor:
            sub_id = self.state["cursor_index"].get(cursor)
            if not sub_id:
                raise InvalidCursorError("未知进度凭据，需要按当前授权重建")
            sub = self.state["subscriptions"].get(sub_id)
            if sub is None:
                raise InvalidCursorError("进度凭据已失效")
            if sub["principal"] != principal or sub["client"] != client:
                raise NotFoundError("进度凭据与客户端不匹配")
            return sub

        sub = self._get_subscription(principal, client)
        if sub is not None:
            return sub
        if not create:
            return None

        token = new_id("prog")
        sub_id = new_id("sub")
        ts = self.state.get("clock", 0)
        sub = {
            "id": sub_id,
            "principal": principal,
            "client": client,
            "progress_token": token,
            "state": "active",
            "reset_reason": None,
            "connected": False,
            "created_seq": self.state["op_seq"],
            "created_ts": ts,
            "last_event_seq": 0,
            "progress_seq": 0,
            "progress_ts": ts,
            "delivery_ids": [],
            "event_delivery_index": {},
            "alarm_heads": {},
            "rebuild": None,
        }
        self.state["subscriptions"][sub_id] = sub
        self.state["client_index"][self._client_key(principal, client)] = sub_id
        self.state["cursor_index"][token] = sub_id

        # 新的 resume 订阅可以读取当前有效授权 since 指向的留存历史；
        # 无权区间和已取消/撤回记录仍不会被复活。
        self._backfill_subscription_history(sub)
        return sub

    def _recover_inflight(self, sub: dict[str, Any]) -> list[str]:
        recovered: list[str] = []
        for delivery_id in sub["delivery_ids"]:
            delivery = self.state["deliveries"][delivery_id]
            if delivery.get("status") == "delivered":
                delivery["status"] = "queued"
                recovered.append(delivery_id)
        return recovered

    def _pump_new_events(self, sub: dict[str, Any]) -> None:
        """兜底扫描；正常发布时已经 fan-out，重启或授权变更后也走同一过滤。"""

        for event in self.state["events"]:
            if int(event["seq"]) <= int(sub.get("last_event_seq", 0)):
                continue
            sub["last_event_seq"] = event["seq"]
            if self._visible_now(sub["principal"], event):
                self._create_event_delivery(sub, event)

    def _backfill_subscription_history(self, sub: dict[str, Any]) -> list[str]:
        created: list[str] = []
        for event in sorted(self.state["events"], key=lambda e: int(e["seq"])):
            # 已处理过的全局水位线不阻止显式 since 授权的定向回填；
            # event_delivery_index 保证同一事件不重复交付，终态不复活。
            if self._visible_now(sub["principal"], event):
                existing = sub["event_delivery_index"].get(event["id"])
                if not existing:
                    delivery = self._create_event_delivery(sub, event)
                    created.append(delivery["id"])
            sub["last_event_seq"] = max(
                int(sub.get("last_event_seq", 0)), int(event["seq"])
            )
        return created

    def _backfill_after_grant(
        self, principal: str, site: str, device: str
    ) -> list[str]:
        refs: list[str] = []
        for sub in self.state["subscriptions"].values():
            if sub["principal"] != principal:
                continue
            for event in sorted(self.state["events"], key=lambda e: int(e["seq"])):
                # 不按事件自带 site 预过滤：设备可能迁站，_visible_now 会按
                # 当前归属和授权厂区做最终判断。
                if event["device"] != device:
                    continue
                if not self._visible_now(principal, event):
                    continue
                if event["id"] in sub["event_delivery_index"]:
                    continue
                delivery = self._create_event_delivery(sub, event)
                refs.append(delivery["id"])
        return refs

    def _create_event_delivery(
        self, sub: dict[str, Any], event: dict[str, Any]
    ) -> dict[str, Any]:
        index = sub.setdefault("event_delivery_index", {})
        existing_id = index.get(event["id"])
        if existing_id:
            return self.state["deliveries"][existing_id]

        key = alarm_key(event["site"], event["alarm"])
        previous_head = sub.get("alarm_heads", {}).get(key)
        delivery_id = new_id("del")
        delivery = {
            "id": delivery_id,
            "sub_id": sub["id"],
            "kind": "event",
            "event_id": event["id"],
            "alarm_key": key,
            "rev": event.get("rev"),
            "created_event_seq": event["seq"],
            "status": "queued",
            "ever_sent": False,
            "revoked": False,
            "cancelled": False,
            "replaces_delivery_id": previous_head["delivery_id"]
            if previous_head
            else None,
            "created_seq": self.state["op_seq"],
        }
        self.state["deliveries"][delivery_id] = delivery
        sub.setdefault("delivery_ids", []).append(delivery_id)
        index[event["id"]] = delivery_id
        sub.setdefault("alarm_heads", {})[key] = {
            "delivery_id": delivery_id,
            "event_id": event["id"],
            "seq": event["seq"],
            "rev": event.get("rev"),
        }
        return delivery

    # ------------------------------------------------------------------
    # 权限变化后的取消/撤回
    # ------------------------------------------------------------------
    def _reevaluate_principal_scope(
        self, principal: str, site: str, device: str, *, reason: str
    ) -> dict[str, list[str]]:
        revocations: list[str] = []
        cancelled: list[str] = []
        for sub in self.state["subscriptions"].values():
            if sub["principal"] != principal:
                continue
            r, c = self._reevaluate_subscription(sub, reason=reason, device=device)
            revocations.extend(r)
            cancelled.extend(c)
        return {"revocations": revocations, "cancelled": cancelled}

    def _reevaluate_all(
        self, *, reason: str, device: str | None = None
    ) -> dict[str, list[str]]:
        revocations: list[str] = []
        cancelled: list[str] = []
        for sub in self.state["subscriptions"].values():
            r, c = self._reevaluate_subscription(sub, reason=reason, device=device)
            revocations.extend(r)
            cancelled.extend(c)
        if revocations or cancelled:
            self._save_locked()
        return {"revocations": revocations, "cancelled": cancelled}

    def _reevaluate_subscription(
        self,
        sub: dict[str, Any],
        *,
        reason: str,
        device: str | None = None,
    ) -> tuple[list[str], list[str]]:
        revocations: list[str] = []
        cancelled: list[str] = []
        for delivery_id in list(sub.get("delivery_ids", [])):
            delivery = self.state["deliveries"].get(delivery_id)
            if not delivery or delivery.get("kind") != "event":
                continue
            if delivery.get("status") == "cancelled":
                continue
            event = self._event_by_id(delivery.get("event_id", ""))
            if event is None:
                # 原始事件已 trim。若它曾发出，撤回只引用 ID，不依赖正文；
                # 若从未发出，则直接取消。
                if delivery.get("ever_sent") and not delivery.get("revoked"):
                    rev = self._ensure_revocation(sub, delivery, reason=reason)
                    if rev:
                        revocations.append(rev["id"])
                else:
                    delivery["status"] = "cancelled"
                    delivery["cancelled"] = True
                    cancelled.append(delivery["id"])
                continue

            if device is not None and event.get("device") != device:
                continue
            if self._visible_now(sub["principal"], event):
                continue
            rev = self._invalidate_event_delivery(
                sub, delivery, reason=reason
            )
            if rev is not None:
                revocations.append(rev["id"])
            elif delivery.get("status") == "cancelled":
                cancelled.append(delivery["id"])
        return revocations, cancelled

    def _invalidate_event_delivery(
        self,
        sub: dict[str, Any],
        delivery: dict[str, Any],
        *,
        reason: str,
    ) -> dict[str, Any] | None:
        delivery["revoked"] = True
        if not delivery.get("ever_sent"):
            delivery["status"] = "cancelled"
            delivery["cancelled"] = True
            return None
        return self._ensure_revocation(sub, delivery, reason=reason)

    def _ensure_revocation(
        self,
        sub: dict[str, Any],
        original_delivery: dict[str, Any],
        *,
        reason: str,
    ) -> dict[str, Any] | None:
        original_id = original_delivery["id"]
        existing_acked = False
        for other_id in sub.get("delivery_ids", []):
            other = self.state["deliveries"][other_id]
            if (
                other.get("kind") == "revocation"
                and other.get("revocation_for_id") == original_id
            ):
                if other.get("status") == "acked":
                    existing_acked = True
                    continue
                # 已在队列或已发出但尚未确认：不要重复生成撤回。
                if other.get("status") == "delivered":
                    return other
                other["status"] = "queued"
                return other

        if existing_acked:
            return None

        revocation_id = new_id("del")
        revocation = {
            "id": revocation_id,
            "sub_id": sub["id"],
            "kind": "revocation",
            "revocation_for_id": original_id,
            "reason": reason,
            "status": "queued",
            "ever_sent": False,
            "created_seq": self.state["op_seq"],
        }
        self.state["deliveries"][revocation_id] = revocation
        sub["delivery_ids"].append(revocation_id)
        original_delivery["revoked"] = True
        return revocation

    # ------------------------------------------------------------------
    # 重建与留存
    # ------------------------------------------------------------------
    def _evaluate_retention(self, sub: dict[str, Any]) -> bool:
        retain_from = self.state.get("trim_retain_from")
        if retain_from is None:
            return False
        if sub.get("state") == "rebuild_pending":
            return False

        unsafe = False
        progress_ts = sub.get("progress_ts")
        if progress_ts is not None and float(progress_ts) < float(retain_from):
            unsafe = True

        for delivery_id in sub.get("delivery_ids", []):
            delivery = self.state["deliveries"][delivery_id]
            if delivery.get("kind") != "event":
                continue
            if delivery.get("status") not in {"queued", "delivered"}:
                continue
            if delivery.get("revoked") or delivery.get("cancelled"):
                continue
            event = self._event_by_id(delivery.get("event_id", ""))
            if event is None or float(event["timestamp"]) < float(retain_from):
                unsafe = True
                break

        if unsafe and sub.get("state") == "active":
            sub["state"] = "reset_required"
            sub["reset_reason"] = "retention_or_missing_progress"
        return unsafe

    def _current_snapshot(self, sub: dict[str, Any]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for alarm in self.state["alarms"].values():
            if alarm.get("status") == "cancelled":
                continue
            if not self._alarm_visible_now(sub["principal"], alarm):
                continue
            items.append(
                {
                    "kind": "snapshot_item",
                    "site": alarm["site"],
                    "device": alarm["device"],
                    "alarm": alarm["alarm"],
                    "rev": alarm["rev"],
                    "status": alarm["status"],
                    "body": alarm.get("body"),
                    "latest_seq": alarm["latest_seq"],
                }
            )
        items.sort(key=lambda item: (item["latest_seq"], item["alarm"]))
        return items

    def _begin_rebuild(
        self, sub: dict[str, Any], seq: int, ts: float | int
    ) -> dict[str, Any]:
        items = self._current_snapshot(sub)
        watermark = self.state["op_seq"]
        rebuild = {
            "id": new_id("rb"),
            "state": "awaiting_client_ack",
            "created_seq": seq,
            "created_ts": ts,
            "watermark_seq": watermark,
            "items": items,
            "item_count": len(items),
            "acked": False,
        }
        sub["rebuild"] = rebuild
        sub["state"] = "rebuild_pending"
        sub["reset_reason"] = None
        return rebuild

    # ------------------------------------------------------------------
    # 渲染
    # ------------------------------------------------------------------
    def _render_event_message(
        self, delivery: dict[str, Any], event: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "kind": "event",
            "delivery_ref": delivery["id"],
            "replaces_delivery_ref": delivery.get("replaces_delivery_id"),
            "rev": event.get("rev"),
            "event": {
                "site": event["site"],
                "device": event["device"],
                "alarm": event["alarm"],
                "rev": event["rev"],
                "status": event["status"],
                "body": event.get("body"),
            },
        }

    def _render_revocation_message(
        self, delivery: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "kind": "revocation",
            "delivery_ref": delivery["id"],
            # 只引用先前不透明交付标识；不附带原告警正文、设备或偏移。
            "clear_ref": delivery["revocation_for_id"],
            "reason": delivery.get("reason", "authorization_changed"),
        }

    # ------------------------------------------------------------------
    # JSONL 事件契约入口
    # ------------------------------------------------------------------
    def dispatch_trace_event(self, event: dict[str, Any]) -> dict[str, Any]:
        event_type = event["type"]
        data = dict(event.get("data", {}))
        data["at"] = event["timestamp"]
        # JSONL 契约使用 move；HTTP/Python 接口使用更明确的 move_device。
        if event_type == "move":
            event_type = "move_device"
        method = getattr(self, event_type, None)
        if method is None or not callable(method):
            raise GatewayError(f"不支持的事件类型: {event_type}")
        return method(**data)


# 便于不同调用习惯导入。
AlertGateway = Service
ForwardingService = Service
Hub = Service
Broker = Service
