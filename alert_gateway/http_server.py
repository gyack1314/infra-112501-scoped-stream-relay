"""标准库 HTTP/JSON 服务与静态浏览器客户端。"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

try:  # 支持 python -m alert_gateway.http_server，也兼容直接运行文件。
    from .core import GatewayError, Service
except ImportError:  # pragma: no cover
    from core import GatewayError, Service  # type: ignore


WEB_ROOT = Path(__file__).resolve().parent / "web"


def create_handler(service: Service):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AlertGateway/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            # 避免默认日志把查询参数/标识写到不必要的位置；仍可通过 --verbose 打开。
            if getattr(self.server, "verbose", False):
                super().log_message(fmt, *args)

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            # 私有唤醒序号不能作为全局流偏移暴露给浏览器。
            payload.pop("_op_seq", None)
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header(
                "Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"
            )
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise GatewayError("请求体必须是 UTF-8 JSON 对象") from exc
            if not isinstance(value, dict):
                raise GatewayError("请求体必须是 JSON 对象")
            return value

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header(
                "Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"
            )
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                if path == "/healthz":
                    self._send_json(200, {"ok": True})
                    return
                if path in {"/", "/index.html"}:
                    self._serve_file(WEB_ROOT / "index.html", "text/html; charset=utf-8")
                    return
                if path == "/app.js":
                    self._serve_file(WEB_ROOT / "app.js", "text/javascript; charset=utf-8")
                    return
                if path == "/styles.css":
                    self._serve_file(WEB_ROOT / "styles.css", "text/css; charset=utf-8")
                    return
                if path == "/api/stream":
                    self._serve_stream(service, parse_qs(parsed.query))
                    return
                if path == "/api/status" or path == "/api/subscriptions":
                    # 查询参数仅做简单 principal/client 过滤。
                    query = parse_qs(parsed.query)
                    principal = query.get("principal", [None])[0]
                    client = query.get("client", [None])[0]
                    self._send_json(200, service.status(principal, client))
                    return
                self._send_json(404, {"ok": False, "error": {"code": "not_found"}})
            except GatewayError as exc:
                self._send_json(exc.http_status, exc.to_payload())
            except Exception as exc:  # pragma: no cover - 服务端保护
                self._send_json(500, {"ok": False, "error": {"message": str(exc)}})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/")
            try:
                payload = self._read_json()
                routes = {
                    "/api/allow": service.allow,
                    "/api/grants/allow": service.allow,
                    "/api/deny": service.deny,
                    "/api/grants/deny": service.deny,
                    "/api/devices/move": service.move_device,
                    "/api/move": service.move_device,
                    "/api/events/publish": service.publish,
                    "/api/publish": service.publish,
                    "/api/trim": service.trim,
                    "/api/retention/trim": service.trim,
                    "/api/open": service.open,
                    "/api/subscriptions/open": service.open,
                    "/api/fetch": service.fetch,
                    "/api/subscriptions/fetch": service.fetch,
                    "/api/ack": service.ack,
                    "/api/subscriptions/ack": service.ack,
                    "/api/disconnect": service.disconnect,
                    "/api/subscriptions/disconnect": service.disconnect,
                    "/api/rebuild-ack": service.rebuild_ack,
                    "/api/subscriptions/rebuild-ack": service.rebuild_ack,
                }
                method = routes.get(path)
                if method is None:
                    self._send_json(404, {"ok": False, "error": {"code": "not_found"}})
                    return
                result = method(**payload)
                self._send_json(200, result)
            except GatewayError as exc:
                self._send_json(exc.http_status, exc.to_payload())
            except TypeError as exc:
                self._send_json(400, {"ok": False, "error": {"message": f"参数错误: {exc}"}})
            except Exception as exc:  # pragma: no cover
                self._send_json(500, {"ok": False, "error": {"message": str(exc)}})

        def _serve_stream(self, service: Service, query: dict[str, list[str]]) -> None:
            principal = query.get("principal", [""])[0]
            client = query.get("client", [""])[0]
            cursor = query.get("cursor", [None])[0]
            local_state = query.get("local_state", ["resume"])[0]
            if not principal or not client:
                raise GatewayError("principal 和 client 查询参数必填")

            opened = service.open(
                principal=principal,
                client=client,
                local_state=local_state,
                cursor=cursor,
            )
            # rebuild 遇到失效凭据时可能回退到当前订阅/新凭据；后续 fetch 用
            # open 返回的有效不透明凭据。
            cursor = opened.get("progress", cursor)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            def write_sse(event: str, payload: dict[str, Any]) -> None:
                body = json.dumps(payload, ensure_ascii=False)
                self.wfile.write(f"event: {event}\n".encode("utf-8"))
                for line in body.splitlines():
                    self.wfile.write(f"data: {line}\n".encode("utf-8"))
                self.wfile.write(b"\n")
                self.wfile.flush()

            write_sse("status", opened)
            last_seq: int | None = None
            try:
                while True:
                    result = service.fetch(
                        principal=principal, client=client, cursor=cursor
                    )
                    last_seq = int(result.get("_op_seq", last_seq or 0))
                    if (
                        result.get("messages")
                        or result.get("state") != "active"
                        or result.get("rebuild")
                    ):
                        public_result = dict(result)
                        public_result.pop("_op_seq", None)
                        write_sse("batch", public_result)
                    current_seq = service.wait_for_change(last_seq, timeout=15.0)
                    if current_seq == last_seq:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

        def _serve_file(self, path: Path, content_type: str) -> None:
            if not path.exists() or not path.is_file():
                self._send_json(404, {"ok": False, "error": {"code": "web_asset_missing"}})
                return
            body = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve(
    host: str = "127.0.0.1",
    port: int = 8787,
    state_path: str | Path | None = None,
    verbose: bool = False,
) -> ThreadingHTTPServer:
    service = Service(state_path)
    httpd = ThreadingHTTPServer((host, port), create_handler(service))
    httpd.verbose = verbose  # type: ignore[attr-defined]
    httpd.service = service  # type: ignore[attr-defined]
    return httpd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动授权感知告警转发服务")
    parser.add_argument(
        "--host", default=os.environ.get("ALERT_GATEWAY_HOST", "127.0.0.1")
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("ALERT_GATEWAY_PORT", "8787")),
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=Path(
            os.environ.get(
                "ALERT_GATEWAY_STATE", ".alert-gateway-state.json"
            )
        ),
    )
    parser.add_argument("--memory", action="store_true", help="不持久化（重启后状态丢失）")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    state = None if args.memory else args.state
    httpd = serve(args.host, args.port, state, args.verbose)
    print(f"alert gateway listening on http://{args.host}:{args.port}")
    print(f"browser console: http://{args.host}:{args.port}/")
    if state:
        print(f"state file: {Path(state).resolve()}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
