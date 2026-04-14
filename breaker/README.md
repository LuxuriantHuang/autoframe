# Breaker

`breaker/` 是一个独立的最小可用闭环，专门针对 `structured_text` 目标做“真实反馈驱动的局部瓶颈突破”。

当前第一版只重点支持 `xmllint --recover @@` 这类 `libxml` XML parser。

## 运行

```bash
python -m integrations.libxml_xmllint_breaker \
  benchmarks/xmllint/out/default/queue/id:000000,time:0,execs:0,orig:seed.xml \
  --project xmllint \
  --target-command "benchmarks/xmllint/target/llvmcov/target --recover @@" \
  --target-file parser.c \
  --target-line 11532
```

如果你只想先验证真实 stderr 闭环，也可以直接对系统 `xmllint` 跑：

```bash
python -m integrations.libxml_xmllint_breaker ./bad.xml \
  --project xmllint \
  --target-command "xmllint --recover @@"
```

输出会包含：

- baseline 的真实返回码和 diagnostics family
- 规则型局部编辑后候选的真实执行结果
- 最优候选路径、动作、评分和反馈摘要

说明：

- `target_file/target_line` 依赖可用的 LLVM 覆盖插桩；拿不到时不会伪造命中。
- 第一版只做规则型 XML 局部修复，不接入 LLM。

