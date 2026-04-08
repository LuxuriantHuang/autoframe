# Flag Variable Recognition Tool - Project Summary

## Project Overview

This project implements a **Flag Variable Recognition** prototype based on the ALGERNON paper design. The tool identifies flag variables (internal state variables) in C/C++ programs through static analysis using LLVM/Clang.

## Project Structure

```
flag_var/
├── flagrec/                    # Main implementation
│   ├── include/                # Header files
│   │   ├── Types.h             # Core data structures
│   │   ├── ConstantFinder.h    # Module A: Flag constants identification
│   │   ├── VariableFilter.h    # Module B: Variable filtering
│   │   ├── FlagIdentifier.h    # Module C: Flag identification
│   │   └── FlagRec.h           # Main orchestrator
│   ├── src/                    # Implementation
│   │   ├── ConstantFinder.cpp
│   │   ├── VariableFilter.cpp
│   │   ├── FlagIdentifier.cpp
│   │   ├── FlagRec.cpp
│   │   └── main.cpp            # CLI tool entry point
│   ├── examples/               # Demo test programs
│   │   ├── demo1_flags.c       # Basic flag variables
│   │   ├── demo2_input.c       # Input variable filtering
│   │   └── demo3_arithmetic.c  # Arithmetic variable filtering
│   ├── tests/                  # Test configuration
│   │   ├── CMakeLists.txt
│   │   └── run_tests.sh.in
│   ├── CMakeLists.txt          # Build configuration
│   ├── build.sh                # Build script
│   ├── quickstart.sh           # Quick start script
│   ├── README.md               # User documentation
│   └── report_template.md      # Technical report template
└── libpng/                     # Test target (libpng source)
```

## Module Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        FlagRecognizer                        │
│                      (Main Orchestrator)                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
┌──────────────┐ ┌──────────┐ ┌─────────────┐
│   Module A   │ │ Module B │ │  Module C   │
│ConstantFinder│ │VarFilter │ │FlagIdenty   │
│              │ │          │ │             │
│ - Enums      │ │ - Taint  │ │ - Match     │
│ - Macros     │ │ - Arith  │ │ - Assigns   │
│ - Const Vars │ │          │ │ - Checks    │
└──────────────┘ └──────────┘ └─────────────┘
        │              │              │
        └──────────────┴──────────────┘
                       │
                       ▼
              ┌────────────────┐
              │   JSON Output  │
              │  + Report.md   │
              └────────────────┘
```

## Key Data Structures

### ConstantGroup
- Groups related constants (enums, macros)
- Shared prefix detection
- Source location tracking

### VarCandidate
- Variable metadata (name, type, function)
- Analysis flags (tainted, arithmetic)
- Assigned constants set

### FlagVariable
- Matched constant group
- Assignment points list
- Check points list
- Confidence score

## Building

```bash
cd flag_var/flagrec
./build.sh
```

This will create the `flagrec` executable in `build/`.

## Running

```bash
# Basic usage
cd flag_var/flagrec/build
./flagrec \
    --compile_commands . \
    --targets ../examples/demo1_flags.c \
    --out ./demo_output

# Quick start demo
cd flag_var/flagrec
./quickstart.sh
```

## Output Format

### flags.json
```json
{
  "constantGroups": [...],
  "flagVariables": [
    {
      "name": "current_mode",
      "type": "int",
      "location": "file.c:25",
      "confidence": 0.85,
      "assignments": [...],
      "checks": [...]
    }
  ],
  "stats": {...}
}
```

### report.md
Human-readable analysis report with:
- Summary statistics
- Flag variable details
- Assignment and check locations

## Demo Programs

### demo1_flags.c
Demonstrates typical flag variable patterns:
- Enum-based flags (`FileMode`, `DeviceState`)
- Macro-based flags (`FLAG_READ`, `FLAG_WRITE`)
- Expected: 4 flag variables identified

### demo2_input.c
Tests input variable filtering:
- `user_input`, `stdin_value` should be filtered (tainted)
- `global_mode`, `config_flags` should be identified as flags

### demo3_arithmetic.c
Tests arithmetic variable filtering:
- `loop_counter`, `byte_count` should be filtered (arithmetic)
- `current_color`, `file_mode` should be identified as flags

## Conservative Design

The tool uses conservative heuristics:
- **Loose grouping**: Only 2+ constants per group
- **Minimal taint**: Direct propagation only
- **Low threshold**: 0.5 confidence default
- **Permissive**: Prefers false positives over false negatives

## Known Limitations

1. No pointer propagation in taint analysis
2. Intra-procedural only (no cross-function)
3. Integer constants only
4. Simple prefix-based clustering

## Future Enhancements

1. **Enhanced taint**: Pointer alias analysis
2. **More patterns**: Bitmask flags, string constants
3. **ML clustering**: Better semantic grouping
4. **Inter-procedural**: Cross-function tracking
5. **Config files**: Per-project settings

## Testing

```bash
cd flag_var/flagrec/build
chmod +x tests/run_tests.sh
./tests/run_tests.sh
```

## Citation

Based on the ALGERNON paper on flag variable identification.

---

**Generated**: February 2025
**Tool Version**: 1.0.0
**LLVM Version**: 10.0+
