# AutoFrame v2 Core

这个目录是从 `autoframe` 当前版本中抽离出来的 v2 核心逻辑最小运行集，适合单独打包成 Docker 镜像。

## 已迁移内容

- `main_v2.py` 入口和 v2 调度/决策逻辑
- `LLM/` 提示词与 LLM 相关模块
- `CoverageTracer.py`、`FuzzerRunner.py`、`state_driven_mapper.py` 等直接依赖
- `semantic_fields/` 语义字段推断模块
- `Excep/`、`pyTracer/`、`parse.py`、`slice.py` 等分析辅助模块
- `batch_process.py`（处理 `compile_commands.json` 到 `src_bear`）
- `tools/bin/llvm-cov`、`tools/bin/llvm-profdata`
- `svf/build/BranchConditionSlicer`
- `svf/build/ir_graph_extractor`

## 未迁移内容

- `AFLplusplus/`
- 大体积 benchmark 结果、日志、实验目录
- `src_new/` 这条新的 workflow 主线
- 完整 `llvm-project/` 源码树与其他未被 v2 直接引用的大型工具目录
- `tracer/`、`ipl-modeling/` 等独立仓库
- `svf/third_party/SVF/` 上游源码树

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

为了把当前目录作为一个可发布的 GitHub 仓库，顶层仓库只保留 AutoFrame 核心代码，不直接纳入以下第三方源码树：

- `AFLplusplus/`
- `llvm-project/`
- `svf/third_party/SVF/`
- `tracer/`
- `ipl-modeling/`

这些目录的本地改动已经导出到 `patches/`，来源和处理方式记录在 [`THIRD_PARTY.md`](THIRD_PARTY.md)。

发布后的默认路径解析规则如下：

- `llvm-cov` 优先使用 `tools/bin/llvm-cov`，其次尝试 `AF_LLVM_COV_BIN` 或系统安装
- `llvm-profdata` 优先使用 `tools/bin/llvm-profdata`，其次尝试 `AF_LLVM_PROFDATA_BIN` 或系统安装
- `opt` 不再随仓库发布；请通过 `AF_LLVM_OPT_BIN` 或系统安装提供
- `afl-showmap` 可通过 `AF_SHOWMAP_BIN` 或 `AF_AFL_PATH` 指定
- SVF slicer 默认尝试 `svf/build/`，也可通过 `AF_SVF_SLICE_PATH` 指定

如果你在新目录里继续保留 benchmark 侧构建链，请注意 `build_others.sh` 现在会间接依赖：

```text
batch_process.py
svf/build/ir_graph_extractor
svf/build/BranchConditionSlicer
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
