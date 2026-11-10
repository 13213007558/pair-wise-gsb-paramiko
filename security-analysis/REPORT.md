# SSH 配置“只 lookup 不连接”是否会执行命令——基于 Paramiko 5.1.0 基线的链路核查

基线：`paramiko` 上游提交 `0e9ccb9`（5.1.0），工作区仅有准备性提交，源码未改动。
结论先行：**“只调用 `SSHConfig.lookup`、不连接服务器”并不等于不执行本地命令。**
只要配置里出现 `Match exec`，`lookup()` 就会在本地真实执行该命令（每条命令在一次
`lookup` 中最多执行两轮）；`ProxyCommand` 则在 `lookup` 阶段只做文本展开，真正起进程
发生在调用方显式构造 `ProxyCommand(...)` 时。没有网络连接 ≠ 没有本地执行。

本报告全部证据由替身（stub）采集：`invoke.run`、`subprocess.Popen`、`socket` 的
DNS 系列函数、`open`/`expanduser` 全部被记录式替身替换，配置中的命令均为不存在的
哨兵路径（`probe-exec`、`/opt/sentinel/proxy-sentinel`），**未执行任何配置提供的真实
外部命令，也没有发生真实网络连接**。复现：

```sh
.venv/bin/python security-analysis/evidence_harness.py     # 8 个场景，证据见 evidence/run.log
.venv/bin/python security-analysis/connect_stage_demo.py   # connect 阶段，证据见 evidence/connect.log
```

## 1. 四个阶段各自会发生什么

### 阶段 A：`parse`（`SSHConfig.parse`，config.py:122）

- 纯文本处理：正则拆 key/value（config.py:140）、`shlex` 切分 `Host`/`Match` 参数
  （config.py:510、521）、构造内部 `_config` 结构。
- `Match exec "..."` 在解析期只被登记为 `{"type": "exec", "param": ...}`
  （config.py:514-556），**不 tokenize、不执行**。
- `ProxyCommand none` 在解析期被转成 `None`（config.py:160-163），避免被当成名为
  `none` 的 shell 命令。
- 唯一的文件读取是 `from_path` 打开配置文件本身（config.py:108）。
- 证据：CASE 1 只有一条 `[OPEN] open(...01-match-exec.conf)`，无 EXEC / DNS / SPAWN。

### 阶段 B：`lookup`（config.py:182；内部两轮 `_lookup`，config.py:248）

`lookup` 做三次实质工作，每一项都可能产生本地副作用：

1. **Match 判定，含 `Match exec` 本地执行。** `_does_match` 遇到 exec 分支时先
   `_tokenize` 再调用 `invoke.run(exec_cmd, hide="stdout", warn=True).ok`
   （config.py:389-398）。退出码 0 视为匹配，非 0 视为不匹配（条件不成立时该 stanza
   的配置不生效，**但命令已经执行过了**，见 CASE 3）。若未安装 invoke，在这里抛
   `ImportError`（config.py:395-396）。
2. **主机名规范化触发 DNS。** `CanonicalizeHostname yes/always` 且点号数不超过
   `CanonicalizeMaxDots` 时，`canonicalize` 对每个 `CanonicalDomains` 候选调用
   `socket.gethostbyname`（config.py:308）；配置了 `AddressFamily inet/inet6` 时改走
   `socket.getaddrinfo`（config.py:584）。解析失败且 `CanonicalizeFallbackLocal yes`
   时回退原名（config.py:318），否则抛 `CouldNotCanonicalize`（config.py:322）。
   规范化成功后会用新名字**再跑一轮完整 `_lookup`**（config.py:239-241），于是
   `Match exec` 在两轮中各执行一次（CASE 5）。
3. **占位符展开。** 最终轮 `_lookup(..., final=True)` 调 `_expand_variables`
   （config.py:277-280、484-503），对每个值调 `_tokenize`（config.py:410）。
   - `~`/`%d` → `os.path.expanduser("~")`（config.py:443）：只做家目录字符串拼接，
     不打开目标文件（`IdentityFile ~/...` 在 lookup 阶段不会被读取）。
   - `%l` → `LazyFqdn`，**仅在被 `str()` 时**解析本地 FQDN：先按 AddressFamily 尝试
     `getaddrinfo`，否则 `socket.getfqdn()`（config.py:596-631）。
   - `%h %p %r %u %L %n %C` 等为纯字符串/哈希替换；`%C` 是 sha1（config.py:449）。
   - 允许替换的令牌按 key 白名单控制（config.py:60-69）：`proxycommand` 只允许
     `~ %h %p %r`，所以 ProxyCommand 里写 `%n` 会原样保留（CASE 6 输出中可见
     `--n %n` 未展开）；`%n` 仅在 `match-exec`/`controlpath` 等键里有效。

**一次 `lookup()` 的执行次数**：`lookup` 先跑首轮 `_lookup`（config.py:224），再跑
final 轮 `_lookup`（config.py:239 或 243）；每轮都会重新评估所有 Match。因此同一条
`Match exec` 在一次 `lookup` 中被执行 **2 次**（已用 mock 计数验证）；若发生规范化，
两轮之间还夹着 DNS 查询，且第二轮以规范化后的主机名再次执行（CASE 5 共 4 条 EXEC）。
重复调用 `lookup` 会重复执行，没有缓存（CASE 4：两次 lookup → 4 条 EXEC）。

### 阶段 C：创建代理（`ProxyCommand(...)`，proxy.py:51-69）

- 构造函数里**立即** `subprocess.Popen(self.cmd, stdin/stdout/stderr=PIPE)`
  （proxy.py:62-68），没有“先准备、连接时再启动”的延迟。`self.cmd` 来自
  `shlex.split(command_line)`（proxy.py:61）。
- 入参 `command_line` 通常就是 `lookup` 结果里已展开的 `proxycommand` 字符串。
  也就是说：**lookup 负责把 `%h/%p/%r/~` 替换成真实值，但绝不 spawn；spawn 是
  应用层显式 `ProxyCommand(conf["proxycommand"])` 的动作。**
- `ProxyCommand none` 时 lookup 返回 `None`（config.py:160-163），调用方应跳过构造；
  本基线不会为 `None` 起进程（CASE 7）。
- 这是纯本地进程创建，不经过任何网络 API。证据：CASE 6 中 lookup 结束时事件只有
  expanduser/getfqdn，构造 `ProxyCommand` 后才出现唯一一条 `[SPAWN]`。

### 阶段 D：`connect`（`SSHClient.connect`，client.py:216）

- **这个类本身不读取 SSHConfig**：`client.py` 中没有任何 `SSHConfig`/proxy 字段
  （全文件 grep 无 `proxy`）。文档也明确“actual SSH connections do not reference
  parsed configs”（sites/docs/api/config.rst）。配置到连接的桥接完全由调用方完成。
- 仅当 `sock is None` 时才走 DNS + TCP：`if not sock:`（client.py:352）→
  `_families_and_addresses` 里的 `socket.getaddrinfo`（client.py:201）→
  `socket.socket(...).connect(addr)`（client.py:358-364）。
- 调用方若把 `ProxyCommand` 实例作为 `sock=` 传入，则 connect 完全跳过 getaddrinfo
  和 socket 创建（connect_stage_demo 步骤 3：两个 mock 均 `called=False`），进程早在
  阶段 C 已启动；connect 之后不再产生新的进程（步骤 4）。
- 真实 SSH 握手（banner、KEX、认证）在 `Transport.start_client` 中发生，属于网络
  数据面，与配置命令执行是两条独立链路。

## 2. 四类配置内容的分阶段对照表

| 配置内容 | parse | lookup | 创建 ProxyCommand | connect |
|---|---|---|---|---|
| `Match exec "cmd"` | 仅登记，不执行 | **本地执行 `invoke.run`**，每轮匹配 1 次、一次 lookup 共 2 次；规范化再翻倍；非零退出只影响 stanza 是否生效 | 无关 | 无关（connect 不看配置） |
| `CanonicalizeHostname` + `CanonicalDomains` | 仅登记 | **发起 DNS**（gethostbyname/getaddrinfo），成功后用新主机名二次 lookup，间接让 Match exec 再执行一轮 | 无关 | 若调用方用规范化后的 HostName 且未给 sock，才再次 DNS/TCP |
| 占位符 `%h %p %r %u %d/~ %C %L %n` | 原样保留 | 纯字符串/哈希展开；`~`/`%d` 触发 expanduser（无文件读取）；`%l` 触发本地 FQDN 的 DNS | 展开后的字符串成为 Popen 的 argv | 无关 |
| `ProxyCommand "cmd ..."` | `none`→`None`，其余存原文 | 仅按白名单展开 `~ %h %p %r`（`%n` 不展开），**不起进程** | **立即 Popen 起本地进程** | 作为 sock 传入时跳过 DNS/TCP；否则 connect 与该命令无关 |

补充：`%l`（LazyFqdn）的 DNS 只在值真的被字符串化时发生，且每次 `_tokenize` 都新建
`LazyFqdn` 实例（config.py:442），没有跨调用缓存，所以 CASE 2/3/4/8 中每条 exec 前都
伴随一次 `getfqdn`。

## 3. 证据索引（security-analysis/）

- `configs/01..05*.conf`：五份短配置，命令均为哨兵，不含可执行的真实外部程序。
- `evidence_harness.py`：记录式替身（EXEC/SPAWN/DNS/OPEN 四类事件），8 个场景：
  - CASE 1 parse 无副作用；CASE 2 exec 条件成立；CASE 3 exec 非零（条件不成立但已执行）；
  - CASE 4 同一配置查询两次；CASE 5/5b 规范化二次匹配（含 DNS 失败回退）；
  - CASE 6 占位符展开与 ProxyCommand 延迟 spawn；CASE 7 `ProxyCommand none`；
  - CASE 8 `%l` 触发本地 FQDN DNS。
- `evidence/run.log`、`evidence/connect.log`：实际运行输出。
- `connect_stage_demo.py`：用 `transport_factory` 替身停在 socket 选择之后，证明
  `sock=` 路径零 DNS、零 socket，且 connect 不读配置。
- 防护有效性：所有 `Popen`/`invoke.run` 均被替身接管；一次误把替身写在 `with` 块外
  的开发期失误曾触发真实 `FileNotFoundError: '/opt/sentinel/proxy-sentinel'`，反证
  哨兵路径在本机不存在、真实执行必然失败，最终版本运行目录下无任何哨兵进程产生。
- 回归：任务指定的 4 个测试文件结果与基线一致——`146 passed, 7 skipped, 13 subtests
  passed`；`tests/test_config.py` 单独为 `113 passed, 7 skipped`。

## 4. 接入建议

### 4.1 服务端自管配置（可信来源、平台负责内容）

可以开放：
- 完整 `parse` + `lookup`，包括 `Match exec`、规范化和全部占位符——但要明确这是
  **服务端主动赋予的执行权**：把配置写入限定目录、命令走受控绝对路径或固定包装器，
  按服务账号最小权限运行，并对 `invoke.run` 做审计（命令行、次数、退出码、耗时）。
- `ProxyCommand` 的完整链路（lookup 展开 → 显式构造 → 作为 sock 连接），同样限定
  可执行文件白名单；注意 spawn 发生在构造函数而非 connect（proxy.py:62），生命周期
  和超时要自己管（`close()` 用 SIGTERM，proxy.py:121-122）。
- 规范化 DNS：接受其外带查询，建议在网络策略上限定可查询的 `CanonicalDomains` 后缀，
  并设置解析超时，避免 `getfqdn`/`gethostbyname` 卡住预览请求。

### 4.2 用户提交配置的“安全预览”（不可信来源）

预览安全边界应停在 **parse + 静态匹配 + 不执行 exec 的 lookup 数据**：
- 允许：`parse`；基于 `Host`/`Match host/originalhost/user/localuser/all/canonical/
  final` 的纯模式匹配；展示原始值与“将会进行的替换”的静态说明。
- 必须禁用/拦截：
  - `Match exec`：不要对用户配置调用真实 `lookup` 的 exec 分支。当前代码没有开关，
    需要在调用层 monkeypatch `paramiko.config.invoke.run` 为“只记录不执行”的替身，
    或在 parse 后扫描 `_config` 中的 exec 项并标记“需要执行才能确定”。
  - `CanonicalizeHostname`：预览环境打桩 `socket.gethostbyname/getaddrinfo/getfqdn`
    （参考 harness 的 `instrumented`），否则一次预览就会向外发 DNS、且改变后续匹配。
  - `ProxyCommand`：只展示展开后的字符串和 argv 预览（用 `shlex.split` 演示），
    **绝不构造 `ProxyCommand`**——构造即 Popen。
  - `%l/%d/~` 等会读取本机环境（FQDN、家目录路径、本地用户名）的令牌：预览输出做
    脱敏或用占位符（如 `<home>`、`<local-fqdn>`）替换，避免泄露宿主机信息。
- 重复执行成本要告知：一次真实 lookup 每条 exec 跑 2 轮、规范化再翻倍，没有缓存；
  预览接口若放行 exec，等于给了提交者一个按查询次数放大的本地执行原语。

### 4.3 只能报告“需要执行才能确定”的信息

以下结果在当前实现里没有纯静态答案，预览应明确标注而非猜测：
- `Match exec` 条件的真假及其 stanza（User、HostName、Port 等）是否生效——取决于
  命令真实退出码（config.py:398）。
- 规范化后的最终 HostName 与二次匹配结果——取决于 DNS 实测（config.py:296-314）；
  `CanonicalizeFallbackLocal no` 时还可能直接抛 `CouldNotCanonicalize`。
- `%l` 的实际值——取决于本机 FQDN 解析（config.py:606-630）。
- `ProxyCommand` 子进程能否启动、握手是否成功——取决于 Popen 与运行时环境
  （proxy.py:62），静态阶段最多报出将执行的 argv。
- `%C` 哈希值虽可静态算出，但它绑定本地主机名、目标名、端口、用户（config.py:444、
  449），预览中应按敏感派生值处理。

### 4.4 落地形态（不构建任意命令隔离系统）

- 预览服务统一在一个注入了替身的进程内运行：stub 掉 `invoke.run`（记录即返回可配置
  的假退出码）、`subprocess.Popen`（仅记录 argv）、三个 DNS 函数和 `expanduser`，
  本仓库 `security-analysis/evidence_harness.py` 可直接作为该注入层的蓝本。
- 输出分两层：静态层（确定可展示的键值、匹配的 Host 模式、将执行的命令文本）与
  动态层（统一标记“需要执行才能确定”的 exec 判定、规范化结果、FQDN、代理可用性）。
- 真正需要动态结果的请求，只对服务端自管配置开放，走 4.1 的受控路径；用户配置的
  动态需求转为审批/工单，而不是在预览接口里临场执行。
