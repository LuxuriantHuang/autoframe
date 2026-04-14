# Hyllfuzz AutoBug Port Analysis

## Executive Summary

`hyllfuzz` uses `AutoBug` in two layers:

1. Build-time instrumentation: build a debug binary, then run `AutoTrace instrument <binary>` to produce a `.autotrace` subject.
2. Run-time agent loop: replay seeds on the `.autotrace` binary, use `autobug get-branch` to discover partially covered conditions, and use `autobug flip-branch` to generate a local source slice for the LLM.

`autoframe` already implements layer 1 and part of layer 2:

- It can build `AutoBug` and instrument benchmark binaries into `.autotrace` artifacts.
- It can replay a reaching seed on the `.autotrace` binary and call `autobug flip-branch` to obtain a slice for one selected roadblock.
- It can validate whether a seed really hits a target line with the `.autotrace` subject.

What is not yet ported is the continuous online agent loop from `hyllfuzz`: queue polling, condition bookkeeping, plateau-triggered solving, and reward updates from generated seeds.

## How Hyllfuzz Uses AutoBug

### 1. Runtime topology

`hyllfuzz/run.py` launches AFL and a separate Python agent in parallel. The agent is given:

- the AFL queue path
- the AFL `fuzzer_stats`
- the `.autotrace` instrumented subject
- the source tree
- the `autobug` analyzer path

See [run.py](/home/lab420/Desktop/benchmarks/hyllfuzz/hyllfuzz/run.py:78).

### 2. Condition tracking

The tracker thread periodically replays new queue entries on the `.autotrace` binary, dumps a trace through `TRACE_DUMP`, then runs:

```bash
autobug get-branch <source_code_dir> <trace_dump> --output /dev/null
```

`AutoBug` writes `BRANCH.dump`, and `hyllfuzz` parses it into:

- `cond_key`
- covered branches
- total branches
- seed IDs that hit each branch

See [task.py](/home/lab420/Desktop/benchmarks/hyllfuzz/hyllfuzz/agent/task.py:44) and [task.py](/home/lab420/Desktop/benchmarks/hyllfuzz/hyllfuzz/agent/task.py:72).

### 3. Plateau solving

Another thread watches `fuzzer_stats:last_path`. Once the fuzzer is stuck for `STUCK_THRESHOLD`, it selects an interesting condition and a seed that reaches it, replays that seed on the `.autotrace` subject, then runs:

```bash
autobug flip-branch <source_code_dir> <trace_dump> \
  --target <file:line> \
  --coverage <covered_branch_list> \
  --output SLICED_CODE.c \
  --comments \
  --window 10
```

That `SLICED_CODE.c` becomes the primary LLM context for generating a new input.

See [main.py](/home/lab420/Desktop/benchmarks/hyllfuzz/hyllfuzz/agent/main.py:68) and [task.py](/home/lab420/Desktop/benchmarks/hyllfuzz/hyllfuzz/agent/task.py:140).

### 4. Build assumptions

`hyllfuzz` always keeps two binaries around:

- AFL-instrumented executable for fuzzing
- debug-built original executable instrumented by `AutoTrace`

The build script explicitly compiles the original binary with `-O0 -g` before calling `./AutoTrace instrument`.

See [build-subject.sh](/home/lab420/Desktop/benchmarks/hyllfuzz/hyllfuzz/build-subject.sh:10).

## What Autoframe Already Has

### 1. Build-time AutoBug support

`autoframe/benchmarks/build_single_dir.sh` already:

- builds `vendor/AutoBug` on demand
- instruments benchmark binaries with `./AutoTrace instrument`
- copies the generated `.autotrace` file into `target/autobug/`

See [build_single_dir.sh](/home/lab420/Desktop/autoframe/benchmarks/build_single_dir.sh:442).

This is the same core build pattern as `hyllfuzz`.

### 2. Single-roadblock AutoBug slicing

`llm_fuzz_system/prompt_builder.py` already performs the key `hyllfuzz` runtime step:

- choose a `reaching_seed`
- replay it on `<project>.autotrace`
- dump a trace via `TRACE_DUMP`
- invoke `autobug flip-branch`
- inject the generated slice into the prompt payload

See [prompt_builder.py](/home/lab420/Desktop/autoframe/llm-fuzz-system/src/llm_fuzz_system/prompt_builder.py:428).

This is effectively a port of `Cond_Solver.slice_code()` plus the trace replay that precedes it.

### 3. Seed validation with AutoTrace replay

`llm_fuzz_system/seed_validation.py` already replays a seed against the `.autotrace` subject and checks whether the target line was hit in the dumped trace.

See [seed_validation.py](/home/lab420/Desktop/autoframe/llm-fuzz-system/src/llm_fuzz_system/seed_validation.py:68).

This covers a chunk of what `hyllfuzz` uses the `.autotrace` binary for during online feedback.

## Gap Analysis

### Already ported

- AutoBug build bootstrap
- `.autotrace` generation
- trace replay using `TRACE_DUMP`
- one-shot `flip-branch` slicing for a chosen target
- replay-based validation of generated seeds

### Not ported

- continuous queue scanner over all new AFL seeds
- `autobug get-branch` based branch-state extraction
- in-memory `cond -> covered_branch -> reaching_seed_ids` database
- plateau monitor driven directly by `fuzzer_stats:last_path`
- reward feedback when generated seeds come back through AFL sync

## Recommended Porting Strategy

### Option A: Minimal port

Recommended first.

Add only `get-branch` extraction and persistent branch-state caching, but keep `autoframe`'s existing cycle runner as the orchestrator.

Concrete shape:

- Add a small module like `autobug_branch_tracker.py`.
- Input: project, AFL queue dir, `.autotrace` subject, source root, command-line args.
- For each new seed:
  - replay with `TRACE_DUMP`
  - run `autobug get-branch`
  - parse `BRANCH.dump`
  - store `cond_key`, covered branch list, and reaching seed metadata
- Feed this cache into target ranking so `prompt_builder` can choose `reaching_seed` without scanning only the latest queue artifacts.

Why this is the right first move:

- It ports the missing `hyllfuzz` logic with the highest leverage.
- It does not fight `autoframe`'s existing `cycle_runner` design.
- It reuses the current one-shot `flip-branch` prompt path instead of replacing it.

### Option B: Plateau-triggered online agent

Add a lightweight daemon loop that mirrors `hyllfuzz`:

- poll `fuzzer_stats`
- poll queue growth
- when stalled, invoke one `run_single_cycle()`

This can be built as a thin wrapper around [cycle_runner.py](/home/lab420/Desktop/autoframe/llm-fuzz-system/src/llm_fuzz_system/cycle_runner.py:1), not as a separate framework.

Why it is viable:

- `autoframe` already has cycle semantics, prompt generation, validation, and feedback logging.
- The missing piece is mainly scheduling and better seed/branch state.

### Option C: Full Hyllfuzz-style transplant

Not recommended.

Avoid porting:

- the global mutable state design from `hyllfuzz/agent/globals.py`
- the thread model as-is
- the “generated seed comes back via sync:agent filename parsing” mechanism

Reasons:

- `autoframe` already has a cleaner module split around diagnosis, prompt building, runtime validation, and loop state.
- A literal transplant would duplicate orchestration logic and create two competing control planes.

## Suggested Implementation Order

1. Add a reusable `AutoBugTraceRunner` helper to centralize `.autotrace` replay and `TRACE_DUMP` handling.
2. Add `get-branch` parsing into a structured cache file under each benchmark, similar to the existing dynamic trace cache.
3. Change reaching-seed selection to prefer seeds proven by AutoBug branch observations, not only current queue heuristics.
4. Expose a CLI subcommand to refresh AutoBug branch state for a project.
5. Only after that, add an optional plateau watcher that calls the existing cycle runner.

## Practical Mapping From Hyllfuzz To Autoframe

| Hyllfuzz piece | Autoframe equivalent | Action |
|---|---|---|
| `.autotrace` build | `build_single_dir.sh` AutoBug functions | already present |
| replay seed with `TRACE_DUMP` | `prompt_builder.py` / `seed_validation.py` | already present |
| `flip-branch` slice | `load_autobug_slice_context()` | already present |
| `get-branch` queue scan | none | port this |
| condition-interest state | none | port this, but store as JSON cache instead of globals |
| plateau monitor | `cycle_runner.py` can be reused | adapt, do not transplant verbatim |

## Bottom Line

The right answer is not “port AutoBug into autoframe”; that has mostly happened already.

The real missing migration is:

- `get-branch` based branch-state accumulation
- a stable reaching-seed database
- optional plateau-driven scheduling on top of the existing `cycle_runner`

If you want the fastest useful move, implement the branch tracker first and wire it into `attach_reaching_seeds()`. That gives `autoframe` the most valuable part of `hyllfuzz` that it still lacks.
