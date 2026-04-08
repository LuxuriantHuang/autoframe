# Dynamic Trace Integration Summary

## Background

The existing tracer can emit a large full-trace stream. That was useful for broad callgraph recovery and roadblock discovery, but it became a startup bottleneck before the slicing workflow could begin.

The goal of this change is to extract only the dynamic facts needed for roadblock slicing:

- the real call path to the target location
- the functions actually observed before the target
- the observed dynamic call edges
- a small executed-location window around the target

## Implemented Changes

- Reused the existing `benchmarks/*/target/trace/*_trace` binaries and their `stderr` event stream.
- Added a streaming trace-summary path instead of storing full per-seed trace text.
- Triggered local dynamic tracing only during roadblock slicing, not during global `get_trace()` collection.
- Used the dynamic summary to:
  - rank static call chains
  - choose a better slicing target when possible
  - post-filter static source slices toward the real execution path
- Preserved the pure static fallback whenever dynamic tracing is unavailable, times out, misses the target, or yields an unusable filtered slice.

## New Interfaces And Data Structures

### `dynamic_trace_summary.py`

- `DynamicTraceSummary`
- `TraceSummaryBuilder`
- `DynamicTraceCache`

### `pyTracer/SeedTracer.py`

- `trace_seed_stream(seed_path, timeo, line_handler)`
- `trace_seed_summary(seed_path, timeo, target_file, target_line, window=20, max_events=50000)`

### `CoverageTracer.py`

- `CoverageTracer.build_dynamic_context_for_roadblock(roadblock, max_seeds=3)`
- `CoverageTracer._select_representative_seeds(...)`
- `CoverageTracer._load_or_build_dynamic_summary(...)`
- `CoverageTracer._aggregate_dynamic_summaries(...)`
- `get_function_slice(..., dynamic_context=None)`
- `_rank_call_chains_with_dynamic_context(call_chains, dynamic_context, fallback_scorer=None)`

## Behavior Changes

- Roadblock analysis may now run a small number of representative seeds through the existing trace binary.
- Dynamic summaries are cached under `benchmarks/<project>/static/dynamic_trace_cache/`.
- Static call-chain ranking now prefers chains that match observed dynamic call paths and dynamic call edges.
- Static source slices are post-filtered toward dynamically observed functions and locations when a valid dynamic context exists.
- If the dynamic path is missing or low quality, the system falls back to the previous static behavior.

## Sync Notes For `af`

- The implementation assumes the trace stream is emitted on `stderr`.
- The parser currently recognizes the existing `[F]`, `[B]`, and `[R]` event formats used by the in-repo trace binaries.
- Cache keys are derived from:
  - project name
  - roadblock `file:line`
  - seed name
  - trace binary metadata
  - source/bitcode fingerprint
- Fallback is required when:
  - the trace times out
  - the target line is not hit
  - no representative seeds are available
  - summary parsing fails
  - the filtered slice becomes too small
- This first version does not change `BranchConditionSlicer` C++ semantics.
- If `AutoBug` trace collection is adopted later, only a new parser/adapter is needed as long as it can populate the same `DynamicTraceSummary` structure.
