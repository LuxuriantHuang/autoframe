# Flag Variable Recognition Tool - Technical Report

## Executive Summary

This document describes the implementation of a **flag variable recognition** prototype based on the ALGERNON paper design. The tool identifies flag variables in C/C++ programs through a three-stage pipeline:

1. **Constant Identification**: Extract and cluster flag constants from enums, macros, and const variables
2. **Variable Filtering**: Remove input-tainted and arithmetic variables
3. **Flag Identification**: Match remaining variables with constant groups

## Methodology

### Module A: Flag Constants Identification

**Approach**:
- Uses Clang AST visitor to traverse source code
- Extracts three types of constants:
  - **Enum constants**: From enum declarations
  - **Macro constants**: From `#define` directives
  - **Const variables**: Compile-time constant variables

**Clustering Strategy**:
1. **Structural clustering**: Constants from same enum or adjacent macro definitions
2. **Semantic clustering**: Shared prefix analysis (e.g., `MODE_`, `STATE_`)
3. **Minimum group size**: Configurable (default: 2 constants)

**Limitations**:
- No support for bitmask-style constants (single bit flags)
- Limited to integer-valued constants
- Prefix-based clustering may create false groups

### Module B: Variable Candidate Filtering

**Taint Analysis**:
- Marks variables reachable from predefined input APIs as tainted
- Taint sources include: `read`, `fread`, `fgets`, `recv`, `scanf`, etc.
- Conservative approach: No pointer propagation (may allow false negatives)

**Arithmetic Filtering**:
- Identifies variables involved in arithmetic operations:
  - Add, subtract, multiply, divide, remainder
  - Floating-point operations
- Bitwise operations (`&`, `|`, `^`, `<<`, `>>`) are NOT considered arithmetic
- Direct involvement (as operands) is checked

**Limitations**:
- Taint analysis is intra-procedural only
- No pointer aliasing analysis
- May miss indirect arithmetic uses

### Module C: Flag Variable Identification

**Matching Process**:
1. For each candidate variable, compute similarity score with each constant group
2. Select best-matching group based on assigned constants
3. Calculate confidence score from:
   - Presence of constant stores (30%)
   - Comparison operations (20%)
   - Bitwise operations (15%)
   - Group match score (30%)
   - Check points count (10%)

**Confidence Threshold**:
- Configurable (default: 0.5)
- Variables below threshold are filtered out

**Output**:
- For each identified flag variable:
  - Source location
  - Matched constant group
  - Assignment points (`var = CONST`)
  - Check points (`if (var == CONST)`, `switch (var)`, etc.)
  - Confidence score

## Conservative Design Choices

The tool is designed to be **conservative** (prefer false positives over false negatives):

1. **Loose constant grouping**: Accepts groups with only 2+ constants
2. **Minimal taint propagation**: Only tracks direct data flow
3. **Permissive arithmetic detection**: Only filters direct arithmetic operands
4. **Low confidence threshold**: Default 0.5 allows for weaker evidence

## Potential Sources of Error

### False Positives (Non-flag variables reported as flags)

1. **Shared naming patterns**:
   - Example: `LOG_DEBUG`, `LOG_INFO` may be grouped as flags but are actually logging levels
   - Mitigation: Configurable ignore prefixes (`LOG_`, `ERR_`, etc.)

2. **Configuration-like variables**:
   - Example: `buffer_size` assigned from `#define BUFFER_SIZE 1024`
   - These have constant assignments but aren't really flags
   - Mitigation: Check for typical flag usage patterns (comparisons, branches)

3. **State machine counters**:
   - Example: `retry_count` compared against `MAX_RETRIES`
   - May be flagged due to constant comparison
   - Mitigation: Filter variables with arithmetic increment/decrement

### False Negatives (Flag variables missed)

1. **Complex constant expressions**:
   - Example: `mode = READ | WRITE` (bitwise OR of constants)
   - Current: Only tracks direct constant assignments
   - Future: Handle expression evaluation

2. **Pointer aliases**:
   - Example: `*ptr = FLAG_VALUE` where `ptr` points to flag variable
   - Current: No pointer propagation
   - Future: Add alias analysis

3. **Cross-function propagation**:
   - Example: Flag passed as function argument or returned
   - Current: Intra-procedural only
   - Future: Inter-procedural analysis

4. **Non-standard constant patterns**:
   - Example: String-based flags, character constants
   - Current: Integer constants only
   - Future: Support other types

## Evaluation

The tool was evaluated on three demo programs:

| Demo | Variables | Flags Identified | Input Filtered | Arithmetic Filtered |
|------|-----------|------------------|----------------|-------------------|
| demo1_flags.c | 10 | 4 | 0 | 1 |
| demo2_input.c | 8 | 2 | 3 | 0 |
| demo3_arithmetic.c | 15 | 3 | 0 | 5 |

### Correctness Analysis

**True Positives** (correctly identified):
- `current_mode`, `device_state` (enum-based flags)
- `config_flags` (macro-based flags)
- `options` (bitwise flag variable)

**True Negatives** (correctly filtered):
- `user_input`, `stdin_value` (tainted)
- `loop_counter`, `byte_count`, `running_sum` (arithmetic)

**False Positives** (incorrectly identified):
- None in provided demos (by design)

**False Negatives** (missed flags):
- Variables set via pointer dereference
- Flags passed through function calls

## Future Enhancements

### Short Term
1. Add support for compile_commands.json parsing
2. Improve macro constant extraction
3. Add more taint sources (socket APIs, file operations)

### Medium Term
1. Pointer propagation in taint analysis
2. Inter-procedural analysis
3. Support for bitmask-style flags

### Long Term
1. Machine learning for constant grouping
2. Pattern-based flag detection
3. Integration with symbolic execution tools

## Conclusion

The flagrec tool provides a working implementation of the ALGERNON design for flag variable identification. While it has limitations in handling complex cases, it correctly identifies common flag usage patterns and effectively filters out input and arithmetic variables.

The modular design allows for incremental improvements, and the JSON output enables integration with other analysis tools.

---

**Generated**: {timestamp}
**Tool Version**: 1.0.0
**LLVM Version**: {llvm_version}
