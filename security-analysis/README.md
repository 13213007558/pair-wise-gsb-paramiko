# security-analysis

针对“只调用 `SSHConfig.lookup` 不连接服务器是否会执行配置命令”的可复现核查。

- `REPORT.md`：完整分析（分阶段链路、对照表、接入建议），结论带 paramiko 源码行号。
- `configs/`：5 份短配置，命令均为不存在的哨兵（`probe-exec`、
  `/opt/sentinel/proxy-sentinel`），不含可运行的真实外部命令。
- `evidence_harness.py`：替身记录进程启动（SPAWN）、DNS、路径读取（OPEN）、
  Match exec（EXEC），覆盖正常匹配、条件不成立、两次查询、规范化二次匹配等 8 个场景。
- `connect_stage_demo.py`：connect 阶段证据，用 transport_factory 替身避免真实握手。
- `evidence/`：两份运行日志。

运行（仓库根目录）：

```sh
.venv/bin/python security-analysis/evidence_harness.py
.venv/bin/python security-analysis/connect_stage_demo.py
```

所有副作用 API 均被记录式替身替换；运行中不会执行配置提供的命令，也不会发起真实
网络连接。
