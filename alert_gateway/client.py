#!/usr/bin/env python3
"""浏览器团队可独立使用的命令行客户端。

它只通过 HTTP/JSON 接口工作，并把服务端签发的不透明 progress token 保存到
本地 state-file；不会解析或伪造进度内容。
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlencode


class GatewayClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8787"):
        self.base_url = base_url.rstrip("/")

    def call(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"ok": False, "error": {"message": raw}}
            parsed.setdefault("http_status", exc.code)
            return parsed
        except urllib.error.URLError as exc:
            return {"ok": False, "error": {"message": f"无法连接服务: {exc}"}}

    def post(self, path: str, **payload: Any) -> dict[str, Any]:
        return self.call("POST", path, payload)

    def get(self, path: str) -> dict[str, Any]:
        return self.call("GET", path)


class LocalCursorStore:
    def __init__(self, path: Path):
        self.path = path
        if path.exists():
            self.data = json.loads(path.read_text(encoding="utf-8"))
        else:
            self.data = {}

    def _key(self, url: str, principal: str, client: str) -> str:
        return f"{url}|{principal}|{client}"

    def get(self, url: str, principal: str, client: str) -> str | None:
        return self.data.get(self._key(url, principal, client), {}).get("cursor")

    def set(
        self, url: str, principal: str, client: str, cursor: str | None
    ) -> None:
        if not cursor:
            return
        self.data[self._key(url, principal, client)] = {
            "principal": principal,
            "client": client,
            "cursor": cursor,
        }
        self.path.write_text(
            json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8"
        )


def print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _cursor_from(result: dict[str, Any]) -> str | None:
    return result.get("progress") if isinstance(result, dict) else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Alert Gateway 独立客户端")
    parser.add_argument("--url", default="http://127.0.0.1:8787")
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(".alert-gateway-client.json"),
        help="保存不透明进度凭据的本地文件",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_client(p: argparse.ArgumentParser) -> None:
        p.add_argument("--principal", required=True)
        p.add_argument("--client", required=True)
        p.add_argument("--use-saved-cursor", action="store_true", default=True)
        p.add_argument("--cursor")

    p_open = sub.add_parser("open", help="建立或恢复订阅")
    add_client(p_open)
    p_open.add_argument("--local-state", choices=["resume", "rebuild"], default="resume")
    p_open.add_argument("--at", type=float)

    p_fetch = sub.add_parser("fetch", help="拉取一批正常事件和撤回通知")
    add_client(p_fetch)
    p_fetch.add_argument("--limit", type=int)
    p_fetch.add_argument("--at", type=float)

    p_ack = sub.add_parser("ack", help="确认一个交付标识")
    add_client(p_ack)
    p_ack.add_argument("--ref", required=True)
    p_ack.add_argument("--at", type=float)

    p_disconnect = sub.add_parser("disconnect", help="逻辑断开，保留进度")
    add_client(p_disconnect)
    p_disconnect.add_argument("--at", type=float)

    p_rebuild = sub.add_parser("rebuild-ack", help="确认已应用重建快照")
    add_client(p_rebuild)
    p_rebuild.add_argument("--rebuild-id")
    p_rebuild.add_argument("--at", type=float)

    p_status = sub.add_parser("status", help="查看订阅进度、待清除标识")
    p_status.add_argument("--principal")
    p_status.add_argument("--client")

    p_watch = sub.add_parser("watch", help="通过 SSE 持续接收正常流和撤回")
    add_client(p_watch)

    p_allow = sub.add_parser("allow", help="管理员授权")
    p_allow.add_argument("--principal", required=True)
    p_allow.add_argument("--site", required=True)
    p_allow.add_argument("--device", required=True)
    p_allow.add_argument("--since", type=float)
    p_allow.add_argument("--at", type=float)

    p_deny = sub.add_parser("deny", help="管理员收回授权")
    p_deny.add_argument("--principal", required=True)
    p_deny.add_argument("--site", required=True)
    p_deny.add_argument("--device", required=True)
    p_deny.add_argument("--at", type=float)

    p_move = sub.add_parser("move", help="设备迁站")
    p_move.add_argument("--device", required=True)
    p_move.add_argument("--from-site", required=True)
    p_move.add_argument("--to-site", required=True)
    p_move.add_argument("--at", type=float)

    p_publish = sub.add_parser("publish", help="生产端发布告警版本")
    p_publish.add_argument("--site", required=True)
    p_publish.add_argument("--device", required=True)
    p_publish.add_argument("--alarm", required=True)
    p_publish.add_argument("--rev", type=int, required=True)
    p_publish.add_argument(
        "--status", choices=["raised", "corrected", "cancelled"], default="raised"
    )
    p_publish.add_argument("--body")
    p_publish.add_argument("--at", type=float)

    p_trim = sub.add_parser("trim", help="压缩留存前缀")
    p_trim.add_argument("--retain-from", type=float, required=True)
    p_trim.add_argument("--at", type=float)

    args = parser.parse_args(argv)
    gateway = GatewayClient(args.url)
    store = LocalCursorStore(args.state_file)

    if args.command == "status":
        if args.principal and args.client:
            result = gateway.get(
                f"/api/status?principal={args.principal}&client={args.client}"
            )
        else:
            result = gateway.get("/api/status")
        print_json(result)
        return 0 if result.get("ok") else 1

    if args.command in {"allow", "deny", "move", "publish", "trim"}:
        payload = {k.replace("_", "-") if False else k: v for k, v in vars(args).items()
                   if k not in {"command", "url", "state_file"} and v is not None}
        # argparse 使用 from_site；HTTP/Python 接口使用 from_site，直接传即可。
        path = {
            "allow": "/api/allow",
            "deny": "/api/deny",
            "move": "/api/devices/move",
            "publish": "/api/events/publish",
            "trim": "/api/trim",
        }[args.command]
        result = gateway.post(path, **payload)
        print_json(result)
        return 0 if result.get("ok") else 1

    cursor = args.cursor
    if not cursor and getattr(args, "use_saved_cursor", False):
        cursor = store.get(args.url, args.principal, args.client)

    if args.command == "watch":
        params = {"principal": args.principal, "client": args.client}
        if cursor:
            params["cursor"] = cursor
        url = f"{args.url}/api/stream?{urlencode(params)}"
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                for raw_line in response:
                    line = raw_line.decode("utf-8").strip()
                    if not line.startswith("data:"):
                        continue
                    payload = json.loads(line[5:].strip())
                    if payload.get("progress"):
                        store.set(
                            args.url,
                            args.principal,
                            args.client,
                            payload["progress"],
                        )
                    print(json.dumps(payload, ensure_ascii=False), flush=True)
        except KeyboardInterrupt:
            return 0
        except urllib.error.URLError as exc:
            print_json({"ok": False, "error": {"message": str(exc)}})
            return 1
        return 0

    if args.command == "open":
        payload = {
            "principal": args.principal,
            "client": args.client,
            "local_state": args.local_state,
        }
        if cursor:
            payload["cursor"] = cursor
        if args.at is not None:
            payload["at"] = args.at
        result = gateway.post("/api/open", **payload)
    elif args.command == "fetch":
        payload = {"principal": args.principal, "client": args.client}
        if args.limit is not None:
            payload["limit"] = args.limit
        if cursor:
            payload["cursor"] = cursor
        if args.at is not None:
            payload["at"] = args.at
        result = gateway.post("/api/fetch", **payload)
    elif args.command == "ack":
        ack_payload = {
            "principal": args.principal,
            "client": args.client,
            "ref": args.ref,
        }
        if args.at is not None:
            ack_payload["at"] = args.at
        result = gateway.post("/api/ack", **ack_payload)
    elif args.command == "disconnect":
        disconnect_payload = {
            "principal": args.principal,
            "client": args.client,
        }
        if args.at is not None:
            disconnect_payload["at"] = args.at
        result = gateway.post("/api/disconnect", **disconnect_payload)
    elif args.command == "rebuild-ack":
        payload = {"principal": args.principal, "client": args.client}
        if args.rebuild_id:
            payload["rebuild_id"] = args.rebuild_id
        if args.at is not None:
            payload["at"] = args.at
        result = gateway.post("/api/rebuild-ack", **payload)
    else:  # pragma: no cover
        parser.error("unknown command")
        return 2

    new_cursor = _cursor_from(result)
    if new_cursor:
        store.set(args.url, args.principal, args.client, new_cursor)
    print_json(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
