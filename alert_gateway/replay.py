"""按仓库 JSONL 事件契约回放演练。

回放层把核心服务返回的不透明交付 ID 映射成 README 约定的 ``out:N``，
方便人工阅读和基于演练脚本的测试；真实 HTTP 客户端拿到的仍是随机不透明 ID。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from trace_io import read_trace  # noqa: E402

try:  # 同时兼容模块运行和直接执行 replay.py。
    from .core import Service  # noqa: E402
except ImportError:  # pragma: no cover
    from core import Service  # type: ignore  # noqa: E402

DEFAULT_TYPES = REPO_ROOT / "data" / "event_types.json"


class TraceRunner:
    def __init__(self, state_path: str | Path | None = None):
        self.service = Service(state_path)
        # key: principal\x1fclient -> {"to_out": {actual: out:N}, "to_actual": ...}
        self.ref_maps: dict[str, dict[str, Any]] = {}
        self.fetch_outputs: list[dict[str, Any]] = []
        self.transcript: list[dict[str, Any]] = []

    def _map_for(self, principal: str, client: str) -> dict[str, Any]:
        key = f"{principal}\x1f{client}"
        if key not in self.ref_maps:
            self.ref_maps[key] = {"order": [], "to_out": {}, "to_actual": {}}
        return self.ref_maps[key]

    def alias_ref(self, principal: str, client: str, actual_ref: str) -> str:
        mapping = self._map_for(principal, client)
        if actual_ref in mapping["to_out"]:
            return mapping["to_out"][actual_ref]
        number = len(mapping["order"]) + 1
        out_ref = f"out:{number}"
        mapping["order"].append(actual_ref)
        mapping["to_out"][actual_ref] = out_ref
        mapping["to_actual"][out_ref] = actual_ref
        return out_ref

    def resolve_ref(self, principal: str, client: str, ref: str) -> str:
        if not isinstance(ref, str) or not ref.startswith("out:"):
            return ref
        mapping = self._map_for(principal, client)
        try:
            return mapping["to_actual"][ref]
        except KeyError:
            # 兼容“按该 client 的交付创建顺序”直接引用的演练。
            try:
                number = int(ref.split(":", 1)[1])
                actual = mapping["order"][number - 1]
            except (ValueError, IndexError) as exc:
                raise KeyError(f"尚未向 {client} 发出 {ref}") from exc
            mapping["to_actual"][ref] = actual
            mapping["to_out"][actual] = ref
            return actual

    def _replace_refs(self, principal: str, client: str, value: Any) -> Any:
        mapping = self._map_for(principal, client)
        to_out = mapping["to_out"]
        if isinstance(value, dict):
            return {k: self._replace_refs(principal, client, v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._replace_refs(principal, client, v) for v in value]
        if isinstance(value, str) and value in to_out:
            return to_out[value]
        return value

    def dispatch(self, event: dict[str, Any]) -> dict[str, Any]:
        event_type = event["type"]
        data = dict(event.get("data", {}))
        timestamp = event["timestamp"]

        if event_type == "ack":
            principal = data["principal"]
            client = data["client"]
            data["ref"] = self.resolve_ref(principal, client, data["ref"])
            result = self.service.ack(at=timestamp, **data)
            record = {"timestamp": timestamp, "type": event_type, "result": result}
            self.transcript.append(record)
            return result

        result = self.service.dispatch_trace_event(event)

        if event_type == "open":
            principal = data["principal"]
            client = data["client"]
            # 握手响应也可能直接带回未确认撤回；按该 client 的 out:N 顺序编号。
            for revocation in result.get("pending_evictions", []):
                actual = revocation.get("delivery_ref")
                if actual:
                    self.alias_ref(principal, client, actual)
            result = self._replace_refs(principal, client, result)

        if event_type == "fetch":
            principal = data["principal"]
            client = data["client"]
            # 先按本批消息顺序分配 out:N；重发的旧 ID 保持原编号。
            for message in result.get("messages", []):
                actual = message.get("delivery_ref")
                if actual:
                    self.alias_ref(principal, client, actual)
            aliased = self._replace_refs(principal, client, result)
            output = {
                "timestamp": timestamp,
                "type": "fetch",
                "principal": principal,
                "client": client,
                "state": aliased.get("state"),
                "progress": aliased.get("progress"),
                "evict_refs": aliased.get("evict_refs"),
                "messages": aliased.get("messages"),
                "rebuild": aliased.get("rebuild"),
            }
            self.fetch_outputs.append(output)
            result = aliased

        record = {"timestamp": timestamp, "type": event_type, "result": result}
        self.transcript.append(record)
        return result

    def run_file(self, path: str | Path) -> list[dict[str, Any]]:
        allowed = set(
            json.loads(DEFAULT_TYPES.read_text(encoding="utf-8"))
        )
        for event in read_trace(Path(path), allowed):
            self.dispatch(event)
        return self.fetch_outputs


def format_fetch_output(output: dict[str, Any]) -> str:
    lines = [
        f"[t={output['timestamp']}] fetch {output['principal']}/{output['client']} "
        f"state={output['state']} progress={output['progress']}"
    ]
    if output.get("evict_refs"):
        lines.append(f"  evict cache refs: {', '.join(output['evict_refs'])}")
    rebuild = output.get("rebuild")
    if rebuild:
        lines.append(
            f"  rebuild {rebuild['id']} awaiting ack, "
            f"items={len(rebuild.get('items', []))}"
        )
    for message in output.get("messages", []):
        if message["kind"] == "event":
            event = message["event"]
            lines.append(
                "  EVENT "
                f"{message['delivery_ref']} "
                f"site={event['site']} device={event['device']} "
                f"alarm={event['alarm']} rev={event['rev']} "
                f"status={event['status']} body={event.get('body')!r}"
            )
        else:
            lines.append(
                "  REVOKE "
                f"{message['delivery_ref']} clear={message['clear_ref']} "
                f"reason={message['reason']}"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="回放告警授权演练 JSONL")
    parser.add_argument("paths", nargs="*", type=Path, help="JSONL 场景文件")
    parser.add_argument("--all", action="store_true", help="回放 data 目录全部场景")
    parser.add_argument("--state", type=Path, help="可选持久化状态 JSON")
    parser.add_argument("--json", action="store_true", help="输出 JSON 结果")
    args = parser.parse_args(argv)

    paths = list(args.paths)
    if args.all or not paths:
        paths = sorted((REPO_ROOT / "data").glob("*.jsonl"))

    results: dict[str, list[dict[str, Any]]] = {}
    for path in paths:
        runner = TraceRunner(args.state)
        results[path.name] = runner.run_file(path)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0

    for name, outputs in results.items():
        print(f"\n=== {name} ===")
        for output in outputs:
            print(format_fetch_output(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
