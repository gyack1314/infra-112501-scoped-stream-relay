from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from alert_gateway.client import GatewayClient
from alert_gateway.core import InvalidCursorError, Service
from alert_gateway.http_server import serve
from alert_gateway.replay import TraceRunner


ROOT = Path(__file__).parent
DATA = ROOT / "data"


def run_trace(name: str, state_path: Path | None = None) -> TraceRunner:
    runner = TraceRunner(state_path)
    runner.run_file(DATA / name)
    return runner


def fetch_at(runner: TraceRunner, timestamp: int, client: str) -> dict:
    matches = [
        item
        for item in runner.fetch_outputs
        if item["timestamp"] == timestamp and item["client"] == client
    ]
    assert len(matches) == 1, (timestamp, client, runner.fetch_outputs)
    return matches[0]


def event_bodies(batch: dict) -> list[str | None]:
    return [message["event"].get("body") for message in batch.get("events", [])]


class ProvidedScenariosTests(unittest.TestCase):
    def test_revocation_during_reconnect_trace(self):
        runner = run_trace("revocation-during-reconnect.jsonl")

        b1_first = fetch_at(runner, 4, "browser-1")
        self.assertEqual(b1_first["messages"][0]["event"]["body"], "A 初始")
        self.assertEqual(b1_first["messages"][0]["delivery_ref"], "out:1")

        b2_batch = fetch_at(runner, 10, "browser-2")
        self.assertEqual(
            [message["kind"] for message in b2_batch["messages"]],
            ["revocation", "event"],
        )
        revocation = b2_batch["messages"][0]
        self.assertEqual(revocation["delivery_ref"], "out:2")
        self.assertEqual(revocation["clear_ref"], "out:1")
        self.assertNotIn("event", revocation)
        self.assertNotIn("body", json.dumps(revocation, ensure_ascii=False))
        self.assertEqual(b2_batch["messages"][1]["event"]["device"], "cam-b")

        b1_resume = fetch_at(runner, 12, "browser-1")
        self.assertEqual(
            [message["kind"] for message in b1_resume["messages"]],
            ["revocation", "event"],
        )
        self.assertEqual(b1_resume["messages"][0]["clear_ref"], "out:1")
        self.assertEqual(b1_resume["messages"][1]["event"]["alarm"], "23")

        b1_later = fetch_at(runner, 15, "browser-1")
        self.assertEqual(len(b1_later["messages"]), 1)
        message = b1_later["messages"][0]
        self.assertEqual(message["kind"], "event")
        self.assertEqual(message["event"]["rev"], 3)
        self.assertEqual(message["event"]["body"], "A 当前")

        serialized = json.dumps(runner.fetch_outputs, ensure_ascii=False)
        self.assertNotIn("A 更正", serialized)
        self.assertNotIn("全局", b1_later["progress"])

    def test_retention_and_relocation_trace(self):
        runner = run_trace("retention-and-device-relocation.jsonl")

        first = fetch_at(runner, 3, "floor")
        self.assertEqual(first["messages"][0]["event"]["site"], "east")

        resume = fetch_at(runner, 9, "floor")
        self.assertEqual(resume["state"], "reset_required")
        self.assertEqual(resume["messages"][0]["kind"], "revocation")
        self.assertEqual(resume["messages"][0]["clear_ref"], "out:1")
        self.assertNotIn("西区设备", json.dumps(resume, ensure_ascii=False))

        rebuild = fetch_at(runner, 11, "floor")
        self.assertEqual(rebuild["state"], "rebuild_pending")
        self.assertIsNotNone(rebuild["rebuild"])
        self.assertEqual(rebuild["rebuild"]["items"], [])
        self.assertEqual(rebuild["messages"][0]["kind"], "revocation")
        self.assertEqual(rebuild["messages"][0]["clear_ref"], "out:1")
        self.assertNotIn("西区设备", json.dumps(rebuild, ensure_ascii=False))


class AuthorizationDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.service = Service()
        self.service.allow("vendor", "east", "cam-a", since=0, at=0)
        self.service.allow("vendor", "east", "cam-b", since=0, at=0)
        self.service.open("vendor", "b1", at=1)

    def test_queued_unsent_is_cancelled_without_revocation(self):
        self.service.publish(
            "east", "cam-a", "1", 1, "raised", "secret", at=2
        )
        self.service.deny("vendor", "east", "cam-a", at=3)
        result = self.service.fetch("vendor", "b1", at=4)
        self.assertEqual(result["messages"], [])
        self.assertEqual(result["evict_refs"], [])
        self.assertEqual(event_bodies(result), [])

    def test_sent_event_gets_opaque_revocation_and_other_device_flows(self):
        self.service.publish("east", "cam-a", "1", 1, "raised", "A", at=2)
        sent = self.service.fetch("vendor", "b1", at=3)
        original_ref = sent["messages"][0]["delivery_ref"]

        self.service.publish("east", "cam-a", "1", 2, "corrected", "A2", at=4)
        self.service.deny("vendor", "east", "cam-a", at=5)
        self.service.publish("east", "cam-b", "9", 1, "raised", "B", at=6)

        batch = self.service.fetch("vendor", "b1", at=7)
        kinds = [m["kind"] for m in batch["messages"]]
        self.assertEqual(kinds, ["revocation", "event"])
        revocation = batch["messages"][0]
        self.assertEqual(revocation["clear_ref"], original_ref)
        self.assertNotIn("event", revocation)
        self.assertNotIn("body", revocation)
        self.assertEqual(event_bodies(batch), ["B"])
        self.assertEqual(batch["messages"][1]["event"]["device"], "cam-b")

    def test_disconnected_denial_survives_rehandshake_and_blocks_gap(self):
        self.service.publish("east", "cam-a", "42", 1, "raised", "A1", at=2)
        first = self.service.fetch("vendor", "b1", at=3)
        original_ref = first["messages"][0]["delivery_ref"]
        self.service.disconnect("vendor", "b1", at=4)

        self.service.deny("vendor", "east", "cam-a", at=5)
        self.service.publish("east", "cam-a", "42", 2, "corrected", "A2", at=6)

        opened = self.service.open("vendor", "b1", at=7)
        self.assertEqual(len(opened["pending_evictions"]), 1)
        self.assertEqual(opened["pending_evictions"][0]["clear_ref"], original_ref)

        batch = self.service.fetch("vendor", "b1", at=8)
        self.assertEqual(len(batch["revocations"]), 1)
        self.assertEqual(batch["events"], [])
        self.assertEqual(event_bodies(batch), [])

        # 恢复授权，但失权区间中的 rev2 不补；只有恢复后的 rev3 可交付。
        self.service.allow("vendor", "east", "cam-a", since=0, at=9)
        self.service.publish("east", "cam-a", "42", 3, "corrected", "A3", at=10)
        later = self.service.fetch("vendor", "b1", at=11)
        self.assertEqual(len(later["events"]), 1)
        self.assertEqual(later["events"][0]["event"]["body"], "A3")
        self.assertEqual(event_bodies(later), ["A3"])

    def test_explicit_since_opens_history_but_denial_gap_remains_closed(self):
        service = Service()
        service.allow("p", "east", "d", since=0, at=0)
        service.publish("east", "d", "a", 1, "raised", "before-gap", at=1)
        service.deny("p", "east", "d", at=2)
        service.publish("east", "d", "a", 2, "corrected", "gap-secret", at=3)
        service.allow("p", "east", "d", since=0, at=4)
        service.publish("east", "d", "a", 3, "corrected", "after-restore", at=5)

        service.open("p", "new-client", at=6)
        batch = service.fetch("p", "new-client", at=7)
        bodies = [m["event"]["body"] for m in batch["events"]]
        self.assertIn("before-gap", bodies)
        self.assertIn("after-restore", bodies)
        self.assertNotIn("gap-secret", bodies)

    def test_ack_is_client_specific(self):
        self.service.open("vendor", "b2", at=1)
        self.service.publish("east", "cam-a", "1", 1, "raised", "A", at=2)
        b1 = self.service.fetch("vendor", "b1", at=3)
        b2 = self.service.fetch("vendor", "b2", at=4)
        ref1 = b1["messages"][0]["delivery_ref"]
        ref2 = b2["messages"][0]["delivery_ref"]
        self.assertNotEqual(ref1, ref2)

        self.service.ack("vendor", "b1", ref1, at=5)
        status1 = self.service.status("vendor", "b1")
        status2 = self.service.status("vendor", "b2")
        self.assertEqual(status1["unacked_event_count"], 0)
        self.assertEqual(status2["unacked_event_count"], 1)

        self.service.deny("vendor", "east", "cam-a", at=6)
        # b1 已确认过正文处理，但权限撤回仍应给出清除通知；b2 也独立收到。
        s1 = self.service.status("vendor", "b1")
        s2 = self.service.status("vendor", "b2")
        self.assertEqual(len(s1["evict_refs"]), 1)
        self.assertEqual(len(s2["evict_refs"]), 1)


class AlarmIdentityAndMoveTests(unittest.TestCase):
    def test_same_alarm_number_in_different_sites_is_distinct(self):
        service = Service()
        service.allow("p", "east", "d", since=0, at=0)
        service.allow("p", "west", "d2", since=0, at=0)
        service.open("p", "c", at=1)
        service.publish("east", "d", "7", 1, "raised", "east-body", at=2)
        service.publish("west", "d2", "7", 1, "raised", "west-body", at=3)
        batch = service.fetch("p", "c", at=4)
        self.assertEqual(len(batch["events"]), 2)
        sites = {m["event"]["site"] for m in batch["events"]}
        self.assertEqual(sites, {"east", "west"})

    def test_move_reevaluates_current_device_attribution(self):
        service = Service()
        service.allow("p", "east", "cam", since=0, at=0)
        service.open("p", "c", at=1)
        service.publish("east", "cam", "7", 1, "raised", "east", at=2)
        sent = service.fetch("p", "c", at=3)
        ref = sent["messages"][0]["delivery_ref"]
        service.disconnect("p", "c", at=4)

        service.move_device("cam", "east", "west", at=5)
        service.publish("west", "cam", "7", 1, "raised", "west", at=6)

        resumed = service.open("p", "c", at=7)
        self.assertEqual(resumed["pending_evictions"][0]["clear_ref"], ref)
        batch = service.fetch("p", "c", at=8)
        self.assertEqual([m["kind"] for m in batch["messages"]], ["revocation"])
        self.assertEqual(batch["events"], [])

    def test_move_with_current_destination_grant_can_keep_device_flow(self):
        service = Service()
        service.allow("p", "east", "cam", since=0, at=0)
        service.allow("p", "west", "cam", since=0, at=0)
        service.open("p", "c", at=1)
        service.publish("east", "cam", "7", 1, "raised", "east", at=2)
        service.fetch("p", "c", at=3)
        service.move_device("cam", "east", "west", at=4)
        service.publish("west", "cam", "8", 1, "raised", "west-visible", at=5)
        batch = service.fetch("p", "c", at=6)
        self.assertEqual([m["kind"] for m in batch["messages"]], ["event"])
        self.assertEqual(batch["events"][0]["event"]["body"], "west-visible")


class RetentionRebuildTests(unittest.TestCase):
    def test_trim_forces_rebuild_and_revocation_survives_until_acked(self):
        service = Service()
        service.allow("p", "e", "d", since=0, at=0)
        service.open("p", "c", at=1)
        service.publish("e", "d", "a", 1, "raised", "body", at=2)
        sent = service.fetch("p", "c", at=3)
        original_ref = sent["messages"][0]["delivery_ref"]
        service.disconnect("p", "c", at=4)
        service.deny("p", "e", "d", at=5)
        service.trim(4, at=6)

        resumed = service.open("p", "c", local_state="resume", at=7)
        self.assertEqual(resumed["state"], "reset_required")
        batch = service.fetch("p", "c", at=8)
        self.assertEqual(batch["state"], "reset_required")
        self.assertEqual(batch["events"], [])
        self.assertEqual(batch["revocations"][0]["clear_ref"], original_ref)
        revocation_ref = batch["revocations"][0]["delivery_ref"]

        rebuilding = service.open("p", "c", local_state="rebuild", at=9)
        rebuild_id = rebuilding["rebuild"]["id"]
        rebuild_batch = service.fetch("p", "c", at=10)
        self.assertEqual(rebuild_batch["state"], "rebuild_pending")
        self.assertEqual(
            rebuild_batch["revocations"][0]["delivery_ref"], revocation_ref
        )
        repeated_before_ack = service.fetch("p", "c", at=10)
        self.assertEqual(
            [m["delivery_ref"] for m in repeated_before_ack["revocations"]],
            [revocation_ref],
        )

        service.rebuild_ack("p", "c", rebuild_id, at=11)
        # rebuild_ack 不替代撤回交付自身的显式 ack；重连后未 ack 撤回仍可恢复。
        service.open("p", "c", at=12)
        redelivered = service.fetch("p", "c", at=13)
        self.assertEqual(
            redelivered["revocations"][0]["delivery_ref"], revocation_ref
        )
        service.ack("p", "c", revocation_ref, at=14)
        service.open("p", "c", at=15)
        after_ack = service.fetch("p", "c", at=16)
        self.assertEqual(after_ack["revocations"], [])


class AlarmVersionTests(unittest.TestCase):
    def test_acked_original_resumes_to_correction(self):
        service = Service()
        service.allow("p", "e", "d", since=0, at=0)
        service.open("p", "c", at=1)
        service.publish("e", "d", "a", 1, "raised", "old", at=2)
        first = service.fetch("p", "c", at=3)
        service.ack("p", "c", first["events"][0]["delivery_ref"], at=4)
        service.disconnect("p", "c", at=5)

        service.publish("e", "d", "a", 2, "corrected", "new", at=6)
        service.open("p", "c", at=7)
        batch = service.fetch("p", "c", at=8)
        self.assertEqual(len(batch["events"]), 1)
        self.assertEqual(batch["events"][0]["event"]["rev"], 2)
        self.assertEqual(batch["events"][0]["event"]["body"], "new")

    def test_denied_correction_becomes_revocation_not_new_body(self):
        service = Service()
        service.allow("p", "e", "d", since=0, at=0)
        service.open("p", "c", at=1)
        service.publish("e", "d", "a", 1, "raised", "old", at=2)
        first = service.fetch("p", "c", at=3)
        service.ack("p", "c", first["events"][0]["delivery_ref"], at=4)
        service.disconnect("p", "c", at=5)

        service.deny("p", "e", "d", at=6)
        service.publish("e", "d", "a", 2, "corrected", "secret-new", at=7)
        opened = service.open("p", "c", at=8)
        self.assertEqual(len(opened["pending_evictions"]), 1)
        batch = service.fetch("p", "c", at=9)
        self.assertEqual([m["kind"] for m in batch["messages"]], ["revocation"])
        self.assertEqual(batch["events"], [])
        self.assertEqual(
            batch["messages"][0]["clear_ref"], first["events"][0]["delivery_ref"]
        )

    def test_cancellation_is_normal_tombstone_the_browser_can_apply(self):
        service = Service()
        service.allow("p", "e", "d", since=0, at=0)
        service.open("p", "c", at=1)
        service.publish("e", "d", "a", 1, "raised", "body", at=2)
        service.fetch("p", "c", at=3)
        service.publish("e", "d", "a", 2, "cancelled", None, at=4)
        batch = service.fetch("p", "c", at=5)
        cancel = [m for m in batch["events"] if m["event"]["status"] == "cancelled"]
        self.assertEqual(len(cancel), 1)


class CursorAndPersistenceTests(unittest.TestCase):
    def test_cursor_is_opaque_and_invalid_cursor_requires_rebuild(self):
        service = Service()
        service.allow("vendor", "east", "cam-a", since=0, at=0)
        opened = service.open("vendor", "browser", at=1)
        token = opened["progress"]
        self.assertTrue(token.startswith("prog_"))
        self.assertNotIn("cam-a", token)
        self.assertNotIn("east", token)
        self.assertNotIn("1", token.split("_", 1)[0])  # prefix only
        with self.assertRaises(InvalidCursorError):
            service.fetch("vendor", "browser", cursor="prog_forged", at=2)

        rebuilt = service.open(
            "vendor",
            "browser",
            local_state="rebuild",
            cursor="prog_expired_unknown",
            at=3,
        )
        self.assertEqual(rebuilt["state"], "rebuild_pending")
        self.assertIsNotNone(rebuilt["rebuild"])

    def test_restart_does_not_replay_unauthorized_content(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "gateway.json"
            first = Service(state_path)
            first.allow("p", "e", "d", since=0, at=0)
            first.open("p", "c", at=1)
            first.publish("e", "d", "secret-alarm", 1, "raised", "SECRET", at=2)
            sent = first.fetch("p", "c", at=3)
            original_ref = sent["messages"][0]["delivery_ref"]
            first.disconnect("p", "c", at=4)

            # 新进程从同一持久化状态启动，然后权限在重启后的服务上收回。
            second = Service(state_path)
            second.deny("p", "e", "d", at=5)
            second.save()

            third = Service(state_path)
            opened = third.open("p", "c", at=6)
            self.assertEqual(
                opened["pending_evictions"][0]["clear_ref"], original_ref
            )
            batch = third.fetch("p", "c", at=7)
            self.assertEqual(len(batch["messages"]), 1)
            self.assertEqual(batch["messages"][0]["kind"], "revocation")
            self.assertEqual(batch["events"], [])

            # 再次“重启”后仍然只有撤回，不恢复普通事件。
            fourth = Service(state_path)
            batch2 = fourth.fetch("p", "c", at=8)
            kinds = [m["kind"] for m in batch2["messages"]]
            self.assertIn("revocation", kinds)
            self.assertNotIn("event", kinds)
            self.assertEqual(batch2["events"], [])


class HttpApiTests(unittest.TestCase):
    def test_http_client_open_publish_fetch_ack(self):
        httpd = serve("127.0.0.1", 0, None)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            client = GatewayClient(f"http://127.0.0.1:{port}")
            self.assertTrue(client.get("/healthz")["ok"])
            self.assertTrue(
                client.post(
                    "/api/allow",
                    principal="p",
                    site="e",
                    device="d",
                    since=0,
                    at=0,
                )["ok"]
            )
            opened = client.post(
                "/api/open", principal="p", client="web", local_state="resume", at=1
            )
            self.assertIn("progress", opened)
            client.post(
                "/api/publish",
                site="e",
                device="d",
                alarm="a",
                rev=1,
                status="raised",
                body="hello",
                at=2,
            )
            fetched = client.post("/api/fetch", principal="p", client="web", at=3)
            self.assertNotIn("op_seq", fetched)
            self.assertNotIn("_op_seq", fetched)
            self.assertEqual(fetched["events"][0]["event"]["body"], "hello")
            ref = fetched["events"][0]["delivery_ref"]
            acked = client.post(
                "/api/ack", principal="p", client="web", ref=ref, at=4
            )
            self.assertTrue(acked["ok"])

            status = json.loads(
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/status?principal=p&client=web"
                ).read().decode("utf-8")
            )
            self.assertEqual(status["unacked_event_count"], 0)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
