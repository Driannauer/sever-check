# sever-check

`sever-check` 是一个面向 OpenClaw 及其他支持 `SKILL.md` 的 Agent 运行环境的 Linux 服务器健康巡检 Skill。它只扫描当前进程可见的本机执行命名空间，生成结构化 JSON 结果，并指导 Agent 输出简明的中文巡检报告。

## 特性

- 只读采集：不会 SSH 到其他主机，也不会使用 `sudo`、重启服务、终止进程或修改系统配置。
- 覆盖 CPU、负载、内存、Swap、磁盘空间、Inode、进程、僵尸进程、systemd、网络、监听端口与近期错误日志。
- 优先使用标准 Linux 接口和 Python 标准库；可选系统命令不可用时会保留部分结果并标明覆盖范围。
- 内置可调整的阈值与严重级别（Healthy / Warning / Critical）。
- 对日志及命令输出中的常见凭据形式进行尽力脱敏。

## 环境要求

- Linux（需要可访问 `/proc`；容器中会看到容器命名空间而非一定是宿主机）。
- Python 3.8 或更高版本；扫描器没有第三方 Python 依赖。
- `df`、`ps` 为常见必需工具；`systemctl`、`ip`、`ss`、`journalctl` 和 `ping` 为可选工具，缺失时会在结果中体现覆盖限制。

## 快速开始

```bash
git clone https://github.com/Driannauer/sever-check.git
cd sever-check

# 将结果写入 JSON 文件
python3 scripts/scan_health.py --output /tmp/server-health-scan.json
```

直接运行会将 JSON 输出到标准输出：

```bash
python3 scripts/scan_health.py
```

常用参数：

```bash
# 不读取 systemd journal
python3 scripts/scan_health.py --no-journal --output /tmp/server-health-scan.json

# 仅在明确需要时，对默认网关执行一次 ICMP 检查
python3 scripts/scan_health.py --ping-gateway --output /tmp/server-health-scan.json

# 自定义磁盘告警阈值
python3 scripts/scan_health.py \
  --disk-warning 75 \
  --disk-critical 85 \
  --output /tmp/server-health-scan.json
```

## 作为 Skill 使用

将本仓库目录作为一个完整的 skill 目录，按你的 Agent 平台的 skill 注册方式安装或挂载。入口说明在 [SKILL.md](SKILL.md)，Agent 界面元数据在 [agents/openai.yaml](agents/openai.yaml)。

Skill 的推荐流程是：

1. 运行 `scripts/scan_health.py` 收集本机只读指标。
2. 检查 JSON 中的 `summary`、`findings` 和 `metrics`。
3. 使用 [references/report-format.md](references/report-format.md) 生成中文巡检报告。

## 默认判定阈值

| 指标 | Warning | Critical |
| --- | ---: | ---: |
| CPU 使用率 | ≥ 85% | ≥ 95% |
| 内存使用率 | ≥ 85% | ≥ 95% |
| 磁盘空间使用率 | ≥ 80% | ≥ 90% |
| Inode 使用率 | ≥ 85% | ≥ 95% |
| 每逻辑 CPU 的 1 分钟负载 | ≥ 1.0 | ≥ 2.0 |
| Swap 使用率（存在 Swap 时） | ≥ 80% | ≥ 95% |
| 僵尸进程 | > 0 | ≥ 10 |

检测到失败的 systemd unit 时默认记为 Warning；最近一小时内观察到至少 20 条 `error..alert` 级别的 journal 条目时也会记为 Warning。任一 Critical 发现会使总体状态为 Critical；否则有 Warning 则为 Warning；其余为 Healthy。

## 输出与限制

扫描器输出 JSON，包括主机信息、原始指标、阈值、发现项和汇总状态。它不会因为某个可选命令缺失而整体失败，但结果应明确反映缺失的覆盖范围。

在容器环境中，CPU、内存、磁盘、进程和网络信息可能仅代表容器命名空间。网关 ping 失败也只能作为辅助证据，因为 ICMP 可能被网络策略拦截。

尽管扫描器会尝试脱敏，结果仍可能包含主机名、网络地址、监听端口或日志摘要。将 JSON 或巡检报告分享给外部人员前，请先复核其中的敏感信息。

## 验证

在 Linux 环境中可先执行以下命令检查脚本语法：

```bash
python3 -m py_compile scripts/scan_health.py
```

## 目录结构

```text
.
├── SKILL.md                     # Skill 行为与安全边界
├── agents/openai.yaml           # Agent 界面元数据
├── assets/icon.svg              # 图标
├── references/report-format.md  # 中文报告模板
└── scripts/scan_health.py       # 只读健康扫描器
```
