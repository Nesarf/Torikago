# MAP — Torikago 的工程地图

未知可执行文件的静态分诊工具。看里面有什么，交给引擎或人决定，中途从不运行被看的那个文件。

## 顶层目录

```
torikago.py            主入口与命令分派
unpack.py              PE / PyInstaller 的解包路径（与 Nanodesu! 同源的做法）
corpus.py              语料仓库：写入、读取、按代分组
corpus_verify.py       --corpus-verify：改一条判据会不会动到既有结论
sample_vault.py        vault：只写一份副本，原件不动
sample_fetch.py        取样本的通道
take_samples.py        取样本的命令行
security_posture.py    --posture：这台机器当前的安全姿态
product_registration.py  产物的声明与登记（让调用方点名自己产出的东西）
provider_malshare.py   外部情报提供方接口（默认关闭）
panel_window.py        窗口与终端渲染，读 panel.json 与 font.json
corpus/                语料事实清单与政策（manifest.jsonl、README）
test/                  35 个测试文件
tools/                 开发期工具（bench_full_scan、pixelart、probe_pyz_rebuild）
.github/workflows/     发布与 CI
```

## 模块职责

`torikago.py` 是唯一入口，负责参数、编排与所有面向人的输出。它把「看」和「判」分开：`--scan` 只说看到了什么，`--handoff` 才把样本递给真实引擎，并**逐字标注判定是别人的**。

`unpack.py` 负责拆 PE 与 PyInstaller 归档，与 Nanodesu! 共享同一类做法，但**语义不同**：这里的变体按构造不能运行（改 PE 头），那边的变体能运行而模块失效。这个差别写进了 `ACTION_CONTRACT.md` 的跨仓库一节，也写成了一条「不比对哈希」的测试。

`corpus.py` 与 `corpus_verify.py` 把「判据改动是否安全」变成可执行的检查：语料记的是事实，改动一条规则之后跑一遍，看哪些既有结论会变。

`security_posture.py` 与 `product_registration.py` 覆盖另外两件事：这台机器此刻的姿态，以及产物归属（谁产出的东西谁负责声明）。

## 数据流

```
输入文件
  -> 静态解析（PE 头、导入、证书、语言、PyInstaller 归档）
  -> 判据（信号分级）-> 报告：stdout + --json
  -> 可选：vault（一份副本）· quarantine（复制并记录）· corpus（事实入账）
  -> 可选：--handoff 交给 Defender / ClamAV，返回引擎的判定与归属
  -> 可选：--staging 生成给 VM 用的转移包
```

## 入口与命令

```
python torikago.py suspect.exe                    # 静态分诊
python torikago.py suspect.exe --handoff defender # 问真引擎，报它的判定
python torikago.py suspect.exe --quarantine ./shuttle
python torikago.py --quarantine-list ./shuttle
python torikago.py --corpus-verify                # 判据改动的安全检查
python torikago.py --posture                      # 本机安全姿态
```

## 测试与验证

`test/` 里 35 个文件，`python -m pytest -q` 一次跑完（462 条通过、29 条跳过）。按职责分四组：解析与解包（`test_torikago`、`test_unpack_*`、`test_parser_regression`）、边界与安全（`test_never_executes`、`test_capabilities`、`test_destructive`、`test_budget`）、语料与判据（`test_corpus*`、`test_calibration`）、人格与输出（`test_persona_table`、`test_boundary_voice`、`test_panel_window`、`test_pixelart`）。

两条最值得记住：`test_never_executes` 保证分析路径不启动进程（`--handoff` 的三个函数是例外，已写入声明）；`test_cross_tool_facts` 保证与 Nanodesu! 对同一文件的事实判断一致。

## 边界

不成为沙盒、不跑样本、不下判定、不称 clean / safe / fixed。`--handoff` 之外，自己不处置；`--quarantine` 只复制。

## 发布

`pyproject.toml` 定义包；tag 触发 `.github/workflows/release.yml`，Trusted Publishing 到 PyPI，GitHub release 带发布记录。sdist 发布前解包并自跑测试。

## 规模（测量值）

```
文件 125 · 代码行 24324 · 依赖边 21 · 测试文件 36 · 外部引用 46
被最多模块引用的：torikago.py (4) · sample_fetch.py (3) · sample_vault.py (3)
```

测试文件数与代码文件数接近一比一，这是这四个工程里测试最密的一个。

数字来自 `library_project op=map`（mega-index-map）对目录的静态清点。它数得出规模与依赖边，数不出职责与边界：
前者在这一节，后者在上面的正文里。
