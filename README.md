# 跨租户订阅流的授权切换与断线续读

转发链路使用厂区、设备和合作方构成授权范围。示例有事件生产端、授权管理端与两个独立浏览器，标识为合成值。

## 事件格式

每个 JSONL 文件是一段独立演练。每行含整数逻辑秒点 timestamp、事件名称 type 和对象 data。同一秒的行按文件顺序排列。时间从零起算。文件里的业务标识只用于建立输入之间的引用。所有场景均可在本地用合成角色重新运行。

- **allow**　管理端安装 principal 对一个 site/device 范围的授权。since 是可授权回看起点，缺省为当前秒点。连续未授权区间中的事件不因重新授权而开放。
- **deny**　管理端收回明确的 site/device 范围。
- **move**　设备从 from_site 到 to_site 的归属变更。授权范围携带站点，同一 device 迁站不会自动转移原站点的授权。告警以首次发布时的站点和告警号为身份。
- **publish**　生产端发出 site/device/alarm 及版本 rev。参考记录中的 rev 递增，status 为 raised、corrected 或 cancelled。
- **open**　client 以 principal 建订阅。local_state 为 resume 或 rebuild，分别表明恢复缓存或主动重建。client 在各 principal 作用域内有自己的进度。
- **fetch**　指定 client 请求接收下一批可见通知。
- **ack**　客户端确认完成一次交付，ref 是浏览器曾经收到的交付标识。在演练中使用 out:N 来引用本次运行自开头起第 N 个发给该 client 的交付标识，实际服务可选择不透明的值。
- **disconnect**　关闭当下的连接，保留 client 身份用于恢复。
- **trim**　生产端前缀压缩到保留时间 retain_from，之前的告警流不再供续读。
- **rebuild_ack**　浏览器确认已经应用针对该 client 发出的缓存重建结果。

## 资料文件

- revocation-during-reconnect.jsonl
- retention-and-device-relocation.jsonl

## 本地资料检查

需 Python 3.11。资料工具使用标准库，无需联网。下列命令读取事件文件并检查封装格式。

```sh
python3 trace_io.py data
python3 -m unittest -v
```

资料工具输出读取的文件、事件数量及首尾秒点。业务状态由使用该事件契约的服务维护。

## 转发服务

仓库现在包含一个仅依赖 Python 标准库的授权感知转发服务：

- `alert_gateway/core.py`：授权、设备迁站、发布、订阅、拉取、确认、撤回、留存和重建的统一事务接口。
- `alert_gateway/replay.py`：把 `data/*.jsonl` 走同一套服务接口回放，并把不透明交付 ID 显示为演练约定的 `out:N`。
- `alert_gateway/http_server.py`：HTTP/JSON API、SSE 实时流和静态浏览器客户端。
- `alert_gateway/client.py`：浏览器团队可独立运行的命令行客户端，本地保存不透明进度凭据。
- `alert_gateway/web/`：无需构建的运维台页面，可查看进度、待清除标识、撤回和正常事件流。

### 运行演练与测试

```sh
python3 -m alert_gateway.replay --all
python3 -m unittest -v
```

回放输出中：

- `EVENT out:N` 是仍可接收的正常告警版本；
- `REVOKE out:M clear=out:N` 表示应清除浏览器缓存中的交付标识 `out:N`；
- `state=reset_required` 表示旧进度已落入被 trim 的前缀，必须重建；
- `state=rebuild_pending` 表示重建快照等待 `rebuild_ack`，此前未确认撤回仍会投递。

### 启动服务和独立客户端

```sh
python3 -m alert_gateway --host 127.0.0.1 --port 8787 \
  --state .alert-gateway-state.json

# 浏览器运维台
open http://127.0.0.1:8787/

# 独立 CLI 客户端
python3 -m alert_gateway.client open \
  --url http://127.0.0.1:8787 \
  --principal vendor --client browser-1 --local-state resume

python3 -m alert_gateway.client fetch \
  --url http://127.0.0.1:8787 \
  --principal vendor --client browser-1

# 持续实时接收；权限收回时，同一条 SSE 连接会收到 revocation
python3 -m alert_gateway.client watch \
  --url http://127.0.0.1:8787 \
  --principal vendor --client browser-1

python3 -m alert_gateway.client ack \
  --url http://127.0.0.1:8787 \
  --principal vendor --client browser-1 --ref del_...
```

CLI 会把服务端签发的 `prog_...` 随机凭据保存到 `.alert-gateway-client.json`；
凭据本身不编码厂区、设备、跳过数量或全局偏移。

### HTTP 接口

所有写接口均接收/返回 JSON：

| 操作 | 路径 |
| --- | --- |
| 授权 | `POST /api/allow`、`POST /api/grants/allow` |
| 收权 | `POST /api/deny`、`POST /api/grants/deny` |
| 设备迁站 | `POST /api/devices/move`、`POST /api/move` |
| 发布告警版本 | `POST /api/events/publish`、`POST /api/publish` |
| 留存压缩 | `POST /api/trim` |
| 握手/重开 | `POST /api/open`、`POST /api/subscriptions/open` |
| 拉取一批 | `POST /api/fetch`、`POST /api/subscriptions/fetch` |
| 确认交付 | `POST /api/ack` |
| 逻辑断开 | `POST /api/disconnect` |
| 确认重建 | `POST /api/rebuild-ack` |
| 订阅状态 | `GET /api/status[?principal=...&client=...]` |
| SSE 流 | `GET /api/stream?principal=...&client=...` |

JSONL 中的 `move` 事件由 `Service.dispatch_trace_event()` 映射到
`Service.move_device()`；其余事件名与核心方法一致。

## 关键一致性规则

1. **同一过滤入口**：实时发布、历史回填、重连恢复和服务重启后的检查都调用
   `_visible_now()`，不会为恢复通道实现另一套更宽松的规则。
2. **收权效果**：从未发出的排队交付立即 `cancelled`；曾经发出的交付生成
   `kind="revocation"` 消息，只带新的撤回交付 ID 和 `clear_ref`，不带正文。
3. **失权区间**：deny 到下一次同范围 allow 之间形成持久化 gap；即使新的
   `since` 更早，gap 中的事件也不会回填。恢复后只交付恢复点之后的新版本。
4. **已取消/已撤回交付不复活**：每个 client 对每个事件只有一个交付记录；
   重新授权后的历史扫描不能把终态交付重新放入队列。
5. **客户端隔离**：交付 ID、进度凭据、ack 和重建状态均按
   `(principal, client)` 隔离；一个浏览器确认不会影响另一个浏览器。
6. **告警身份**：内部键为 `(site, alarm)`，因此相同告警号在不同厂区互不相同。
7. **设备归属**：设备迁站后按“当前站点 + 设备”重新匹配授权；旧站点授权不会
   自动转移成新站点授权。当前站点无授权时，已发出的相关交付进入撤回流程。
8. **留存与重建**：客户端进度早于 `trim.retain_from` 或有仍需正文重放的未确认
   普通交付时，订阅进入 `reset_required`。`open(local_state="rebuild")` 返回当前
   授权范围的可用快照；`rebuild_ack` 前 fetch/SSE 仍会交付未确认撤回。
9. **持久化**：指定 `--state` 后，授权世代、gap、设备关系、订阅进度、交付和
   ack 状态均原子写入 JSON。重启时会再次按当前授权重估所有未终态交付。
