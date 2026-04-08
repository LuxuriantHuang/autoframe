# Third-Party Components

This repository is published as the AutoFrame core workspace. Large third-party
source trees and local experiment data are intentionally excluded from the main
Git history.

## Excluded third-party repositories

### `AFLplusplus/`

- Type: upstream dependency with local tuning
- Handling: excluded from the top-level Git history
- Recommended sync model: standalone checkout or submodule
- Local changes tracked here: [`patches/AFLplusplus-config.patch`](patches/AFLplusplus-config.patch)

### `llvm-project/`

- Type: large upstream fork with local `llvm-cov` changes
- Handling: excluded from the top-level Git history
- Recommended sync model: fork plus patch application
- Local base commit recorded from the local checkout: `c987950fa`
- Local changes tracked here: [`patches/llvm-project-llvm-cov.patch`](patches/llvm-project-llvm-cov.patch)

### `svf/third_party/SVF/`

- Type: upstream SVF checkout used by the local slicer build
- Handling: excluded from the top-level Git history
- Recommended sync model: standalone checkout or submodule
- Local changes tracked here: [`patches/svf-third-party-SVF.patch`](patches/svf-third-party-SVF.patch)

### `tracer/`

- Type: standalone tracing/instrumentation repository
- Handling: excluded from the top-level Git history
- Recommended sync model: standalone checkout or submodule
- Local changes tracked here: [`patches/tracer.patch`](patches/tracer.patch)

### `ipl-modeling/`

- Type: separate project with its own repository lifecycle
- Handling: excluded from the top-level Git history
- Recommended sync model: clone separately when the workflow needs it

## Excluded generated data

The following are also excluded because they are generated, host-specific, or
too large for a source repository:

- `.env`
- `benchmarks/*`
- `log/`
- `llm_log/`
- build/output directories
- `tools/bin/opt`

## Rehydration notes

To recreate a full local environment, prepare the external dependencies beside
this repository:

- place or clone `AFLplusplus/`
- place or clone `llvm-project/` and rebuild the custom `llvm-cov` if needed
- place or clone `svf/third_party/SVF/`
- place or clone `tracer/`
- place or clone `ipl-modeling/` when the IPL workflow is required

The patch files under `patches/` capture the local modifications that were
present in those third-party trees at publish time.
