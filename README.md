# 网络拓扑生成与验证工具

戴伟琦 · D24090600669

这是我的计算机网络课程拓展作业。我用 Codex 将 DeepSeek API 接入 Agent，把自然语言需求转换为拓扑描述，再用 Python 校验地址、接口、VLAN 和路由配置，生成 Packet Tracer（PT）配置文件。我在 PT 中搭建和配置设备，随后导入实测命令输出，由 Agent 对照验收条件判断结果。

## 评估与实测结果

- **模型评估**  
  我用同一组 10 个基准需求运行了两批评估。两批首次静态校验均通过 9 项。完成各批次的生成流程后，第一批有 9 项通过拓扑与需求校验，第二批有 10 项通过。两批中的 2 个矛盾需求均返回了澄清请求  
  [第一批指标](evaluations/20261030-v2/metrics.json) · [第二批指标](evaluations/20261030-v2-json-budget/metrics.json) · [逐项结果](evaluations/20261030-v2-json-budget/results.json)
- **UC06 同网段连通性**  
  我在 Packet Tracer 中将 PC0（`192.168.1.1/24`）和 PC1（`192.168.1.2/24`）分别接到 SW1 的 `Fa0/1` 和 `Fa0/2`。两台主机互相 ping，两个方向均为 4 发 4 收，丢包率为 0%  
  [Packet Tracer 工程](runs/20261030T090245Z-3490e939/evidence/UC06.pkt) · [拓扑截图](runs/20261030T090245Z-3490e939/evidence/UC06-topology.png) · [PC0 到 PC1](runs/20261030T090245Z-3490e939/evidence/PC0-ping-PC1.png) · [PC1 到 PC0](runs/20261030T090245Z-3490e939/evidence/PC1-ping-PC0.png)
- **RIPv1 和 RIPv2**  
  我在同一套三路由器拓扑上做对照。RIPv1 阶段双向 ping 均为 4 发 0 收，R0 缺少 `192.168.16.128/26`，R1 缺少 `192.168.16.0/25`。切换到 RIPv2 后，双向 ping 均为 4 发 4 收，R0 经 `30.0.0.2` 学到前者，R1 经 `30.0.0.1` 学到后者，四项验收均通过  
  [RIPv1 工程](labs/route-validation/evidence/ripv1/RIPv1.pkt) · [RIPv2 健康工程](labs/route-validation/evidence/ripv2/9c9fd44e-RIPv2-healthy.pkt) · [R0 路由表](runs/20261030T132441Z-c768bb37/evidence/imports/check-03-c2772db6.txt) · [R1 路由表](runs/20261030T132441Z-c768bb37/evidence/imports/check-04-d4c9eb54.txt)
- **子网掩码配置错误与修复**  
  在 RIPv2 健康基线上，我把 R0 的 `G0/0` 掩码从 `/25` 改为 `/26`，PC0 到 PC1 的 ping 变为 4 发 0 收。Agent 根据我导入的 `show running-config` 定位到掩码不一致，并生成候选补丁。我审阅后输入 `CONFIRM`，在 PT 中手动恢复 `/25`。复测时双向 ping 均为 4 发 4 收，两份路由表也通过了检查  
  [故障时的 ping](runs/20261030T132441Z-c768bb37/evidence/imports/check-01-e615b369.txt) · [修复候选](runs/20261030T132441Z-c768bb37/repairs/R0/candidate-1.cfg) · [修复后的 ping](runs/20261030T132441Z-c768bb37/evidence/imports/check-01-5933599a.txt) · [修复后的工程](labs/route-validation/evidence/repaired/0ffaa9b2-RIPv2-_repaired.pkt)
- **OSPF**  
  我将 R0 与 R1 直连链路两端的 `G0/2` 接口的 OSPF 代价设为 64。实测中，两台路由器都经 R2 学到对端子网，路由表显示累计代价为 3。PC0 的 `tracert` 依次经过 R0、R2、R1，最后到达 PC1。双向 ping 均为 4 发 4 收，五项验收全部通过  
  [OSPF 工程](labs/route-validation/evidence/ospf/a32a2691-OSPF.pkt) · [R0 路由表](runs/20261030T132549Z-b88473b6/evidence/imports/check-03-f55fa54c.txt) · [R1 路由表](runs/20261030T132549Z-b88473b6/evidence/imports/check-04-21f6f39f.txt) · [PC0 路径记录](runs/20261030T132549Z-b88473b6/evidence/imports/check-05-d7c4cb3e.txt)

模型评估统计拓扑生成和静态校验，PT 验收依据实际采集的命令输出。原始模型响应、生成的配置和导入文本保存在 `runs/`。路由实验的结果索引和工程文件见 [实测目录](labs/route-validation/)

## 安装和离线试跑

我用 Python 3.13 和 Packet Tracer 8.2 开发和测试。复现时使用 Python 3.11 或更新版本，在项目根目录执行以下命令。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python agent.py validate cases/CASE01/expected.yaml
.venv/bin/python agent.py compile cases/CASE01/expected.yaml --out runs/offline-case01
```

这一步直接使用 CASE01 的参考拓扑，无需 API Key。编译成功后，在 `runs/offline-case01/draft/` 中可查看两台路由器的 CLI、主机地址表 `pc-addresses.csv`、连线表 `links.csv` 和操作与验收说明。再次编译时，给 `--out` 指定一个新目录。

## 接入 API 并生成配置

```bash
.venv/bin/python agent.py configure
.venv/bin/python agent.py doctor
```

`configure` 隐藏输入 API Key，保存到本地 `.env`。提交包不含密钥和虚拟环境。默认服务为 `https://api.deepseek.com`，模型为 `deepseek-flash`。同名 `LLM_*` 环境变量优先于 `.env`。

`doctor` 不联网。需要检查接口时运行 `agent.py check-api`，会产生一次短请求费用。

配置好 API 后，可以用同一个用例的自然语言需求生成拓扑。

```bash
.venv/bin/python agent.py generate \
  --request-file cases/CASE01/request.txt \
  --contract-file cases/CASE01/contract.json
```

每次生成保存在独立的 `runs/` 目录。`topology.yaml` 是拓扑描述，`draft/` 内有分设备 CLI、地址表、连线表和验收计划。`contract.json` 用于检查需求是否被保留，人工参考 `expected.yaml` 不发送给模型。

单次需求最多调用模型三次。校验失败时将错误反馈给模型；输出截断时保留原文并提高预算重试。V2 默认输出上限为 16384 tokens，最高 65536。供应商过滤的回复不会自动重试。

## 审阅并发布配置

我先核对 `topology.yaml` 和 `draft/` 中的地址表、连线表及各设备 CLI。下面以离线试跑生成的 `runs/offline-case01` 为例。使用 API 生成时，把它替换为终端显示的运行目录。

```bash
.venv/bin/python agent.py release runs/offline-case01
```

Agent 会核对拓扑和草稿的哈希，并重新检查待发布的 CLI。审阅后，在提示处单独输入大写 `CONFIRM` 并回车，配置文件会写入本次运行目录的 `packet-tracer/`。

以 CASE01 为例，我在 Packet Tracer 中按 `links.csv` 连线，按 `pc-addresses.csv` 设置主机 IP、掩码和网关，再把 `R0.cfg` 和 `R1.cfg` 分别粘贴到对应路由器的 CLI。配置完成后，按 `操作与验收.md` 运行测试。

## 验收与诊断

我根据 `verification-plan.json` 中的检查编号和源设备，在 PT 执行对应命令。以下命令以 `check-01` 的源设备为 PC0 为例。先把单次完整输出保存为 `PC0-ping.txt`，再将 `runs/本次目录` 替换为实际运行目录。

```bash
.venv/bin/python agent.py verify runs/本次目录 \
  --check-id check-01 --device PC0 --output PC0-ping.txt
```

程序支持英文 ping、tracert/traceroute 和 `show ip route` 输出。结果为 `passed`、`failed` 或 `unknown`。`passed` 表示符合断言；例如 RIPv1 对照中的“不可达”符合预期，也会通过。原始文本和 SHA-256 一并保存。

路由前缀不存在用 `present:false` 表达。分页、输出截断、目标不符或无法识别的路由行会保留为 `unknown`。PC 输出中的设备身份依赖操作人的来源声明；Cisco 输出还会核对提示符。

遇到失败时，我先保留失败输出，再导入对应设备的完整运行配置进行诊断。

```bash
.venv/bin/python agent.py diagnose runs/本次目录 \
  --device R0 --running-config R0-running.txt --failed-check-id check-01
.venv/bin/python agent.py release-repair runs/本次目录 --device R0
```

目前可定位接口主 IPv4 地址或掩码错配、遗漏的 `network` 声明和静态路由。导入 `show running-config` 时，保留命令开头和最后的设备提示符。我审阅候选并输入 `CONFIRM` 后，在 PT 里手动应用补丁，再重跑同一项检查并导入新输出。

```bash
.venv/bin/python agent.py verify runs/本次目录 \
  --check-id check-01 --device PC0 --output PC0-ping-after-repair.txt
.venv/bin/python agent.py verify-repair runs/本次目录 \
  --device R0 --check-id check-01
```

`verify-repair` 使用本轮确认后新导入的验收结果。Agent 最多生成三轮候选。

## 路由实验流程

我用同一套三台路由器、两台 PC 的拓扑依次完成 RIPv1、RIPv2、错掩码修复和 OSPF。切换协议时，迁移配置会移除旧协议，并按当前阶段设置或恢复 OSPF 链路开销。

```bash
.venv/bin/python agent.py lab prepare --out labs/本次实测
.venv/bin/python agent.py lab release labs/本次实测
.venv/bin/python agent.py lab collect-stage labs/本次实测 --stage ripv1
.venv/bin/python agent.py lab status labs/本次实测
```

审阅配置后，在 `lab release` 的提示处输入 `CONFIRM`。采集时，我按终端提示在 PT 执行命令，把完整输出粘贴回来，再另起一行输入 `__END__`。RIPv2 健康基线的四项检查通过后，按手册执行错掩码演练和复测。 [路由实验操作手册](labs/route-validation/开始实测.md)

在同一工程、同一配置下继续采集时，可用 `collect-stage --resume`。程序会核对已归档的原始输出，仅提示尚未达到阶段预期的检查。切换工程或修改配置后，重新采集全阶段。应用新的修复候选后，按手册重新采集对应的修复验收项。

提交包中的 `audit/route-validation/` 是原机实验快照，包含历史绝对路径。换机器后请用上面的 `lab prepare` 新建实验目录，原始审计文件保留原样。

## 测试和数据集

我将拓扑、地址和预期行为整理成 10 个自然语言需求。评估通过改变拓扑规模、路由协议和访问条件，检查 Agent 生成的方案是否满足各用例的约束。

| 网络场景 | 评估用例 | 检查内容 |
|---|---|---|
| IPv4 无分类编址与静态路由 | CASE01、CASE02 | 核对不同拓扑规模下的子网划分、主机网关和静态路由下一跳 |
| RIPv1 与 RIPv2 | CASE03、CASE04 | 在同一套 VLSM 编址下检查两种版本的路由前缀与主机可达性 |
| OSPF | CASE05、CASE06 | 检查单区域场景的链路代价和路径选择，以及多区域场景的区域配置 |
| HTTP | CASE07、CASE08 | 检查直连和跨网段两种场景的主机地址、网关与 HTTP 服务计划 |
| 扩展 ACL | CASE09、CASE10 | 检查单条 ICMP 策略和多条访问控制规则的顺序与应用方向 |

我把 `request.txt` 交给 DeepSeek 生成拓扑，用本地的 `contract.json` 校验需求约束，并用 `expected.yaml` 做离线回归。这些用例用于评估，没有用于训练或微调模型。另外两个矛盾需求用来检查模型是否会要求澄清。 [用例索引](cases/index.json)

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python agent.py validate cases/CASE03/expected.yaml
```

我用合成数据跑单元测试，用参考拓扑检查离线编译。单元测试无需 API。真实模型响应和 PT 命令输出用于各自的评估。

```bash
# 真实模型评估，会计费；输出目录必须是新的。
.venv/bin/python agent.py evaluate --out evaluations/new-evaluation \
  --include-challenges --max-calls 30

# 用当前校验器检查已有响应，不调用API。
.venv/bin/python agent.py recheck evaluations/20261030-v2-json-budget \
  --out evaluations/new-recheck
```

正确要求澄清计为该项通过。评估分别统计首次静态检查通过率和首次设备部署通过率。没有实测样本的指标留空。

## 范围与限制

支持 PC-PT、Server-PT、2960 和 2911，IPv4、access/trunk VLAN、静态路由、RIPv1/v2、OSPF、HTTP 服务计划和扩展 ACL。HTTP 页面仍在 PT 中人工检查。

暂未实现 NAT、BGP、IPv6、IPsec、SVI 和路由器子接口，也未接入 Batfish。默认 IOS 输出兼容范围以测试为准，未知配置会阻止生成修复补丁。DSL 0.1 和旧 UC06 入口保留，普通生成默认使用 0.2。
