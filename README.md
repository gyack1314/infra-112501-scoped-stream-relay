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
