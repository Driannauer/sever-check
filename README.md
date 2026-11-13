# sever-check

`sever-check` 是一个面向 OpenClaw 及其他支持 `SKILL.md` 的 Agent 运行环境的 Linux 服务器健康巡检 Skill。它只扫描当前进程可见的本机执行命名空间，生成结构化 JSON 结果，并指导 Agent 输出简明的中文巡检报告。

## 特性

- 只读采集：不会 SSH 到其他主机，也不会使用 `sudo`、重启服务、终止被检查的业务进程或修改系统配置；超时只终止扫描器自己启动的采集命令。
- 覆盖 CPU、负载、内存、Swap、磁盘空间、Inode、进程、僵尸进程、系统级和当前用户级 systemd、网络及监听端口。
- 默认检查最近 **24 小时** journal，包含 emerg 至 err（优先级0–3），按记录计数并保留来源聚合、截断和采集状态。
- 使用 Python 标准库及常见 Linux 接口；命令有超时和输出上限，采集失败保留部分结果并标明限制。
- 内置可调整的阈值与严重级别（Healthy / Warning / Critical）。
- 区分采集缺失与“不适用”：例如未配置 Swap、EFI 文件系统不提供 Inode 容量。
- 对常见凭据形式尽力脱敏，以0600权限原子写入报告，避免读取半写入结果或覆盖符号链接的目标。
- 中文报告采用标题层级、重点加粗和“资源与服务”三列表格，集中呈现异常的证据与建议，不附固定的“检查范围”结尾。

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

# 临时检查最近一小时日志（默认是24小时）
python3 scripts/scan_health.py --journal-since '1 hour ago'

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
2. 确认命令成功，且 `scanned_at_utc`、`completed_at_utc` 属于本次执行；失败后不可把旧文件当作新结果。
3. 检查 JSON 中的 `summary`、`findings`、`thresholds`、`coverage` 和 `metrics`。
4. 使用 [references/report-format.md](references/report-format.md) 生成中文巡检报告。

在已有授权的定时任务中使用时，由任务框架按其投递配置发送报告；扫描器本身不发送消息、不创建定时任务。

## 判定与阈值

默认阈值由扫描器维护；可通过 `python3 scripts/scan_health.py --help` 查看可用参数，实际阈值以每次输出的 `thresholds` 为准。参数会校验范围、数值有效性与告警/严重阈值顺序。

任一 Critical 发现会使总体状态为 Critical；否则有 Warning 则为 Warning；其余为 Healthy。默认日志窗口为24小时，观察到至少20条错误或更高级别记录时产生告警；单条优先级0–2日志也需要核查，但历史记录本身不证明当前宕机。核心指标缺失、默认日志采集失败会产生覆盖告警；主动使用 `--no-journal` 会记录覆盖限制。

## 输出与限制

扫描器输出 schema 1.3 JSON，包括主机信息、开始/完成时间、耗时、原始指标、阈值、发现项、汇总状态和集中覆盖限制。可选命令失败不会让整个扫描直接退出，但不能将未知数据当作零异常。

`metrics.services.user` 表示当前用户级 systemd，包括可能在该层运行的 OpenClaw Gateway。日志数量在截断时是下界，单元/优先级聚合只代表保留样本；不能将错误日志条数等同于登录尝试总次数。非回环端口绑定也不能直接证明公网可达。

在容器环境中，CPU、内存、磁盘、进程和网络信息可能仅代表容器命名空间。网关 ping 失败也只能作为辅助证据，因为 ICMP 可能被网络策略拦截。

尽管扫描器会尝试脱敏，结果仍可能包含主机名、网络地址、监听端口或日志摘要。将 JSON 或巡检报告分享给外部人员前，请先复核其中的敏感信息。

## 验证

在 Linux 环境运行回归测试：

```bash
python3 -B -m unittest discover -s tests -v
```

测试覆盖缺失指标、阈值边界、用户级服务、日志计数与截断、超时和输出上限、脱敏及报告原子写入。需要试跑时使用独立输出路径，避免覆盖定时任务正在使用的报告。

## 目录结构

```text
.
├── SKILL.md                     # Skill 行为与安全边界
├── agents/openai.yaml           # Agent 界面元数据
├── assets/icon.svg              # 图标
├── references/report-format.md  # 中文报告模板
├── scripts/scan_health.py       # 只读健康扫描器
└── tests/test_scan_health.py    # 回归测试
```
