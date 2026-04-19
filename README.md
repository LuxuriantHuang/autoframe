# AutoFrame v2 Core

这个目录是从 `autoframe` 当前版本中抽离出来的 v2 核心逻辑最小运行集，适合单独打包成 Docker 镜像。

## 已迁移内容

- `main_v2.py` 入口和 v2 调度/决策逻辑
- `LLM/` 提示词与 LLM 相关模块
- `CoverageTracer.py`、`FuzzerRunner.py`、`state_driven_mapper.py` 等直接依赖
- `semantic_fields/` 语义字段推断模块
- `Excep/`、`pyTracer/`、`parse.py`、`slice.py` 等分析辅助模块
- `batch_process.py`（处理 `compile_commands.json` 到 `src_bear`）
- `svf/build/BranchConditionSlicer`
- `svf/build/ir_graph_extractor`

## 未迁移内容

- 大体积 benchmark 结果、日志、实验目录
- `src_new/` 这条新的 workflow 主线
- 各 benchmark 的输入、编译产物和实验输出

## 目录约定

代码默认把当前目录识别为 `AF_HOME`。运行时如果不在当前目录执行，可以显式传：

```bash
export AF_HOME=/app
```

项目数据默认期待位于：

```text
benchmarks/<project>/
├── static/static.json
├── src/
├── src_bear/
├── build_others.sh
├── target/
└── in/
```

`config.py` 已改成在缺少 `static.json` 时允许导入成功，便于先构建镜像；真正运行时仍需要把对应 benchmark 数据挂载进来。

## 第三方依赖处理

顶层仓库通过 submodule 管理第三方源码树，默认指向 `LuxuriantHuang` 账号下的镜像仓库：

- `AFLplusplus/`
- `svf/third_party/SVF/`
- `tracer/`
- `ipl-modeling/`
- `AutoBug/`

第三方来源、镜像仓库、补丁文件和构建约定记录在 [`THIRD_PARTY.md`](THIRD_PARTY.md) 和 [`third_party/repos.tsv`](third_party/repos.tsv)。

新机器建议使用下面的流程初始化：

```bash
git submodule update --init --recursive
./scripts/bootstrap-third-party.sh --sync-urls --init --apply-patches
./scripts/bootstrap-third-party.sh --build
```

如果目标机器只配置了 HTTPS 凭证，可以改成：

```bash
PROTOCOL=https ./scripts/bootstrap-third-party.sh --sync-urls --init --apply-patches
```

发布后的默认路径解析规则如下：

- `afl-showmap` 可通过 `AF_SHOWMAP_BIN` 或 `AF_AFL_PATH` 指定
- SVF slicer 默认尝试 `svf/build/`，也可通过 `AF_SVF_SLICE_PATH` 指定

如果你在新目录里继续保留 benchmark 侧构建链，请注意 `build_others.sh` 现在会间接依赖：

```text
batch_process.py
svf/build/ir_graph_extractor
svf/build/BranchConditionSlicer
```

统一构建第三方依赖时，默认脚本会按顺序构建：

- `AFLplusplus`
- `tracer`
- `svf/third_party/SVF`
- 本地 `svf/` 包装工具
- `AutoBug`
- `ipl-modeling`

你也可以按组件执行，例如：

```bash
./scripts/bootstrap-third-party.sh --build --component tracer --component svf/third_party/SVF
```

## 常用环境变量

推荐直接复制 `.env`：

```bash
cp .env.example .env
```

然后在 `.env` 里填写，例如：

```dotenv
AF_OUTPUT_DIR=out
AF_MODEL_PROVIDER=qwen-max
AF_MODEL_NAME=
DASHSCOPE_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
DASHSCOPE_API_KEY=your_key
AF_TEST_MODE=0
```

如果你会切换不同 provider，建议把每家都各自配置一组 `BASE_URL/API_KEY`，和原始 `autoframe` 的 `config.py` 逻辑保持一致：

```dotenv
# DeepSeek
DEEPSEEK_BASE_URL=https://api.deepseek.com/beta
DEEPSEEK_API_KEY=

# Qwen / DashScope
DASHSCOPE_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
DASHSCOPE_API_KEY=

# Kimi / Moonshot
MOONSHOT_BASE_URL=https://api.moonshot.cn/v1
MOONSHOT_API_KEY=

# GLM / BigModel
BIGMODEL_BASE_URL=https://open.bigmodel.cn/api/paas/v4/
BIGMODEL_API_KEY=
```

兼容保留的通用覆盖项：

```dotenv
AF_BASE_URL=
AF_API_KEY=
```

`config.py` 会在启动时自动加载当前目录下的 `.env`。

## 本地运行

```bash
pip install -r requirements.txt
python main_v2.py libxml -o out -- --input @@
```

其中 `libxml` 这类 `project` 参数建议在运行时显式传入，而不是写进 `.env`。

## Docker

构建：

```bash
docker build -t autoframe-v2-core .
```

运行时建议把 benchmark 数据目录挂进去，例如：

```bash
docker run --rm \
  --env-file .env \
  -v /path/to/benchmarks:/app/benchmarks \
  autoframe-v2-core \
  python main_v2.py libxml -o out
```
