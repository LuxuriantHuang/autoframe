# Third-Party Components

This repository is published as the AutoFrame core workspace. Third-party
source trees are tracked as Git submodules so new machines can rehydrate the
same layout without manual cloning.

## Tracked third-party repositories

### `AFLplusplus/`

- Type: upstream dependency with local tuning
- Handling: mirrored to `LuxuriantHuang/AFLplusplus` and tracked as a submodule
- Local changes tracked here: [`patches/AFLplusplus-config.patch`](patches/AFLplusplus-config.patch)

### `svf/third_party/SVF/`

- Type: upstream SVF checkout used by the local slicer build
- Handling: mirrored to `LuxuriantHuang/SVF` and tracked as a submodule
- Local changes tracked here: [`patches/svf-third-party-SVF.patch`](patches/svf-third-party-SVF.patch)

### `tracer/`

- Type: standalone tracing/instrumentation repository
- Handling: mirrored to `LuxuriantHuang/tracer` and tracked as a submodule
- Local changes tracked here: [`patches/tracer.patch`](patches/tracer.patch)

### `ipl-modeling/`

- Type: separate project with its own repository lifecycle
- Handling: tracked as a submodule

### `AutoBug/`

- Type: standalone repository used by the tracing pipeline
- Handling: tracked as a submodule

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

To recreate a full local environment:

```bash
git submodule update --init --recursive
./scripts/bootstrap-third-party.sh --sync-urls --init --apply-patches
./scripts/bootstrap-third-party.sh --build
```

The bootstrap script reads [`third_party/repos.tsv`](third_party/repos.tsv) and
can also target a different GitHub account mirror:

```bash
GITHUB_USER=<your-account> PROTOCOL=https ./scripts/bootstrap-third-party.sh --sync-urls --init
```

The patch files under `patches/` capture the local modifications that were
present in those third-party trees at publish time.
