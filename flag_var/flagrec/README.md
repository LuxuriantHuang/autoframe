# Flag Variable Recognition Tool (flagrec)

A static analysis tool for identifying **flag variables** in C/C++ programs based on the ALGERNON paper design.

## Overview

Flag variables are internal state variables that:
- Take values from a limited set of compile-time constants (enums, macros, const variables)
- Are typically not directly derived from user input
- Appear primarily in conditional checks (`==`, `!=`, bitwise operations)
- Are not involved in arithmetic operations

## Architecture

The tool is organized into three main modules:

### Module A: Flag Constants Identification
- Extracts constants from:
  - Enum declarations
  - `#define` macros
  - `const` variable declarations
- Clusters constants into groups based on:
  - Structural proximity (same enum, adjacent definitions)
  - Semantic naming (shared prefixes like `MODE_`, `TYPE_`)

### Module B: Variable Candidate Filtering
- Collects all global and local variables from LLVM IR
- Filters out:
  - **Input-tainted variables**: Variables reachable from input APIs (`read`, `fread`, `recv`, etc.)
  - **Arithmetic variables**: Variables involved in add/sub/mul/div operations

### Module C: Flag Variable Identification
- Matches remaining candidates with constant groups
- Collects:
  - Assignment points (`var = CONST`)
  - Check points (`if (var == CONST)`, `switch (var)`, `var & CONST`)
- Calculates confidence scores

## Building

### Prerequisites
- CMake >= 3.10
- LLVM/Clang >= 10.0
- C++14 compatible compiler

```bash
# Ubuntu/Debian
sudo apt-get install cmake clang-10 llvm-10-dev libclang-10-dev

# Verify installation
llvm-config --version  # Should be >= 10.0
clang++ --version
```

### Build Steps

```bash
cd flag_var/flagrec
mkdir build
cd build
cmake ..
make
```

The executable `flagrec` will be created in the `build` directory.

## Usage

### Basic Usage

```bash
./build/flagrec \
    --compile_commands /path/to/build \
    --targets /path/to/source.c \
    --out ./output
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--compile_commands` | Path to build directory with `compile_commands.json` | Required |
| `--targets` | Comma-separated source files to analyze | Required |
| `--out` | Output directory | `./flagrec_output` |
| `--verbose` | Enable verbose output | Off |
| `--min-confidence` | Minimum confidence score (0.0-1.0) | 0.5 |
| `--min-group-size` | Minimum constants per group | 2 |
| `--conservative` | Enable conservative mode | Off |
| `--ignore-prefixes` | Constant prefixes to ignore | `LOG_,ERR_,WARN_,INFO_,DEBUG_` |
| `--save-intermediates` | Save intermediate results | Off |

### Example

```bash
# Analyze a single file
./build/flagrec \
    --compile_commands . \
    --targets examples/demo1_flags.c \
    --out ./demo1_results \
    --verbose

# Analyze multiple files with custom settings
./build/flagrec \
    --compile_commands /path/to/project/build \
    --targets src/main.c,src/utils.c,src/device.c \
    --out ./analysis_results \
    --min-confidence 0.7 \
    --min-group-size 3
```

## Output

### `flags.json`

JSON file containing identified flag variables:

```json
{
  "constantGroups": [
    {
      "id": "group_0",
      "commonPrefix": "MODE_",
      "type": "enum",
      "location": "demo.c:10",
      "constants": [
        {"name": "MODE_READ", "value": 0, "location": "demo.c:12"},
        {"name": "MODE_WRITE", "value": 1, "location": "demo.c:13"}
      ]
    }
  ],
  "flagVariables": [
    {
      "name": "current_mode",
      "type": "int",
      "function": "<global>",
      "location": "demo.c:25",
      "groupId": "group_0",
      "confidence": 0.85,
      "assignments": [
        {"location": "demo.c:45", "value": 1}
      ],
      "checks": [
        {"location": "demo.c:47", "type": "equal", "value": 1}
      ]
    }
  ],
  "stats": {
    "totalConstants": 12,
    "totalGroups": 3,
    "totalVariables": 45,
    "filteredInputVars": 8,
    "filteredArithmeticVars": 15
  }
}
```

### `report.md`

Human-readable markdown report with:
- Summary statistics
- Detailed flag variable information
- Confidence scores
- Assignment and check locations

## Demo Programs

Three demo programs are provided in `examples/`:

### `demo1_flags.c`
Shows typical flag variable usage with enums and macros. Expected to identify:
- `current_mode`
- `device_state`
- `options` (local)
- `config_flags`

### `demo2_input.c`
Demonstrates input variable filtering. Variables like `user_input`, `stdin_value`, `buffer` should be filtered out (tainted).

### `demo3_arithmetic.c`
Shows arithmetic variable filtering. Variables like `loop_counter`, `byte_count`, `running_sum` should be filtered out.

## Running Tests

```bash
cd flag_var/flagrec/build
cmake .. -DBUILD_TESTS=ON
make
chmod +x tests/run_tests.sh
./tests/run_tests.sh
```

## Project Structure

```
flagrec/
├── include/           # Header files
│   ├── Types.h               # Core data structures
│   ├── ConstantFinder.h      # Module A: Constants
│   ├── VariableFilter.h      # Module B: Filtering
│   ├── FlagIdentifier.h      # Module C: Identification
│   └── FlagRec.h             # Main orchestrator
├── src/               # Implementation
│   ├── ConstantFinder.cpp
│   ├── VariableFilter.cpp
│   ├── FlagIdentifier.cpp
│   ├── FlagRec.cpp
│   └── main.cpp               # CLI entry point
├── examples/          # Demo programs
│   ├── demo1_flags.c
│   ├── demo2_input.c
│   └── demo3_arithmetic.c
├── tests/             # Test configuration
│   ├── CMakeLists.txt
│   └── run_tests.sh.in
└── CMakeLists.txt     # Build configuration
```

## Limitations and Future Work

### Current Limitations
1. **No pointer propagation**: Taint analysis is conservative and doesn't track through complex pointer operations
2. **Limited constant patterns**: Only handles integer constants and simple enums
3. **Basic clustering**: Groups only by simple prefix and proximity heuristics
4. **No inter-procedural analysis**: Each function is analyzed independently

### Potential Improvements
1. **Enhanced taint analysis**: Add pointer propagation and value-range tracking
2. **More constant types**: Support bitmask constants, character constants, string-based flags
3. **Stronger semantic clustering**: Use ML techniques for better constant grouping
4. **Inter-procedural analysis**: Track flag variables across function boundaries
5. **Configuration file support**: Allow per-project settings and custom taint sources

## Citation

Based on concepts from the ALGERNON paper on flag variable identification.

## License

See LICENSE file for details.

## Contact

For issues or questions, please use the project's issue tracker.
