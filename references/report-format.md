# Health report format

Render the final report in Simplified Chinese unless the user asks for another language.

Use this structure:

```markdown
# 服务器健康巡检报告

- 主机：<hostname>
- 扫描时间：<time>
- 总体状态：Healthy | Warning | Critical
- 运行环境：宿主机 / 容器命名空间无法确认时明确说明

## 1. 结论摘要
<2-5 bullets, critical first>

## 2. 核心指标
| 项目 | 当前值 | 状态 | 判断依据 |
|---|---:|---|---|
| CPU | ... | ... | ... |
| Load | ... | ... | ... |
| 内存 | ... | ... | ... |
| Swap | ... | ... | ... |
| 磁盘 | ... | ... | ... |
| Inode | ... | ... | ... |

## 3. 服务与进程
- systemd 状态、failed units
- 僵尸进程
- CPU/内存占用靠前的进程
- 检测到的 OpenClaw systemd unit（如有）

## 4. 网络与监听端口
- 网卡/地址概览
- 默认路由与网关
- DNS nameserver
- 监听端口摘要；不要把长列表逐行复制，突出异常或高风险暴露

## 5. 最近错误日志
- 对 journal 的 error..alert 条目做聚类摘要
- 不复制凭据、令牌或完整敏感日志
- 区分“单次错误”与“持续重复错误”

## 6. 异常与建议
按 Critical -> Warning -> Info 排序。每项写：现象、证据、可能影响、建议动作。
不要把建议动作当作已经执行。不要自动执行修复。
```

## Interpretation rules

- Use script-generated threshold findings as the baseline, but inspect raw metrics before concluding.
- Treat ICMP gateway failure as weak evidence because ping may be blocked.
- Treat a systemd failed unit as a warning until its relevance is understood; stale failed units can exist.
- Do not mark a host healthy if key metrics were unavailable. State the missing coverage explicitly.
- For containerized OpenClaw, state that the scan sees only the namespace visible to OpenClaw unless host visibility is confirmed.
- Keep recommendations concrete and read-only by default. If a remediation command would mutate the server, show it only when the user explicitly asks for remediation and label it as a proposed command.
