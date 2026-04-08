# Repository Guidelines

## Project Structure & Module Organization

Core source lives in [`src/`](./src), with the current extractor implementation concentrated in `src/main.cpp`. Build configuration is defined in `CMakeLists.txt`. Helper automation lives in [`scripts/`](./scripts), notably `scripts/extract_with_svf.sh` for running SVF and merging its output. Generated artifacts belong in [`build/`](./build) and analysis results belong in [`output/`](./output); treat both as disposable. [`third_party/SVF/`](./third_party/SVF) vendors the SVF dependency and should only be edited when updating or debugging the bundled toolchain. [`backup/`](./backup) contains reference snapshots, not active code.

## Build, Test, and Development Commands

Configure against LLVM 10:

```bash
cmake -S . -B build -DLLVM_DIR=$(llvm-config-10 --prefix)/lib/cmake/llvm
```

Build the extractor:

```bash
cmake --build build -j
```

Run on LLVM IR or bitcode:

```bash
build/ir_graph_extractor input.bc -o output/run1
```

Run with SVF pointer-analysis enrichment:

```bash
build/ir_graph_extractor input.bc -o output/run1 --run-svf
```

Or use the wrapper script:

```bash
./scripts/extract_with_svf.sh input.bc output/run1
```

## Coding Style & Naming Conventions

Use C++17 and keep compatibility with LLVM 10 APIs. Match the existing style in `src/main.cpp`: 2-space indentation, braces on the same line, `UpperCamelCase` for structs, `lowerCamelCase` for functions and local helpers, and `ALL_CAPS` only for shell variables. Prefer small, composable helpers over large inline blocks. Keep filesystem paths configurable through flags instead of hardcoding new machine-specific values.

## Testing Guidelines

There is no formal unit-test suite yet. Validate changes by rebuilding and running the extractor on a small `.ll` or `.bc` sample, then inspect `static.json`, `callgraph.dot`, and `cfg/*.dot` under a fresh `output/` subdirectory. When fixing analysis behavior, add or reuse a minimal repro input and describe the expected graph change in your PR.

## Commit & Pull Request Guidelines

Git history is not available in this workspace, so follow a simple imperative style such as `Add SVF callsite merge fallback`. Keep commits scoped to one concern. PRs should include: purpose, build/test commands run, representative input used for validation, and sample output paths or screenshots when graph structure changes. Call out any LLVM or SVF version assumptions explicitly.
