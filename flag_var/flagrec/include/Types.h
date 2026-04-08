//===-- Types.h - Flag Variable Recognition Data Structures ----*- C++ -*-===//
///
/// \file
/// This file defines the core data structures used in the flag variable
/// recognition system based on the ALGERNON paper design.
///
//===----------------------------------------------------------------------===//

#ifndef FLAGREC_TYPES_H
#define FLAGREC_TYPES_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <optional>

namespace flagrec {

/// Source location in the original source code
struct SourceLocation {
  std::string file;
  unsigned line;
  unsigned column;

  SourceLocation() : line(0), column(0) {}
  SourceLocation(const std::string &f, unsigned l, unsigned c = 0)
      : file(f), line(l), column(c) {}

  std::string toString() const {
    return file + ":" + std::to_string(line);
  }

  bool operator<(const SourceLocation &other) const {
    if (file != other.file) return file < other.file;
    return line < other.line;
  }
};

/// Type of flag constant
enum class ConstantType {
  Enum,       // Enum value
  Macro,      // #define macro
  ConstVar    // const variable
};

/// A single flag constant
struct FlagConstant {
  std::string name;           // Constant name (e.g., "MODE_READ")
  int64_t value;              // Numeric value
  ConstantType type;          // Source type
  SourceLocation location;    // Definition location
  std::string groupName;      // Parent group (enum name or macro prefix)

  FlagConstant() : value(0), type(ConstantType::Macro) {}

  FlagConstant(const std::string &n, int64_t v, ConstantType t,
               const SourceLocation &loc, const std::string &grp = "")
      : name(n), value(v), type(t), location(loc), groupName(grp) {}
};

/// A group of related flag constants
struct ConstantGroup {
  std::string id;                    // Group identifier
  std::vector<FlagConstant> constants;  // Constants in this group
  std::string commonPrefix;          // Common name prefix (e.g., "MODE_")
  ConstantType type;                 // Primary type of group
  SourceLocation location;           // Group definition location

  /// Get all values in this group
  std::set<int64_t> getValues() const {
    std::set<int64_t> values;
    for (const auto &c : constants) {
      values.insert(c.value);
    }
    return values;
  }

  /// Check if a value belongs to this group
  bool contains(int64_t val) const {
    for (const auto &c : constants) {
      if (c.value == val) return true;
    }
    return false;
  }
};

/// Type of check point
enum class CheckType {
  Equal,      // var == CONST
  NotEqual,   // var != CONST
  BitAnd,     // var & CONST
  BitOr,      // var | CONST
  Switch      // switch(var) case CONST:
};

/// A point where flag variable is used in a condition
struct CheckPoint {
  SourceLocation location;
  CheckType checkType;
  int64_t comparedValue;    // The constant being compared against
  std::string condition;    // Pretty-printed condition

  CheckPoint() : checkType(CheckType::Equal), comparedValue(0) {}
};

/// An assignment point (var = CONST)
struct AssignmentPoint {
  SourceLocation location;
  int64_t assignedValue;
  std::string assignment;    // Pretty-printed assignment

  AssignmentPoint() : assignedValue(0) {}
};

/// A flag variable candidate
struct FlagVariable {
  std::string name;                // Variable name
  std::string typeName;            // Type name (int, enum, etc.)
  std::string function;            // Containing function (empty if global)
  SourceLocation location;         // Declaration location
  std::string groupId;             // Associated constant group
  std::vector<AssignmentPoint> assignments;
  std::vector<CheckPoint> checks;
  double confidence;              // Confidence score [0.0, 1.0]

  /// Get all constants assigned to this variable
  std::set<int64_t> getAssignedConstants() const {
    std::set<int64_t> consts;
    for (const auto &a : assignments) {
      consts.insert(a.assignedValue);
    }
    return consts;
  }

  /// Get all constants checked in conditions
  std::set<int64_t> getCheckedConstants() const {
    std::set<int64_t> consts;
    for (const auto &c : checks) {
      consts.insert(c.comparedValue);
    }
    return consts;
  }
};

/// Result of flag variable analysis
struct AnalysisResult {
  std::vector<ConstantGroup> constantGroups;
  std::vector<FlagVariable> flagVariables;
  std::map<std::string, std::string> metadata;  // Analysis metadata

  /// Statistics
  struct Stats {
    int totalConstants;
    int totalGroups;
    int totalVariables;
    int filteredInputVars;
    int filteredArithmeticVars;

    Stats() : totalConstants(0), totalGroups(0), totalVariables(0),
              filteredInputVars(0), filteredArithmeticVars(0) {}
  } stats;

  AnalysisResult() {}

  /// Find a constant group by ID
  const ConstantGroup* findGroup(const std::string &id) const {
    for (const auto &g : constantGroups) {
      if (g.id == id) return &g;
    }
    return nullptr;
  }
};

} // namespace flagrec

#endif // FLAGREC_TYPES_H
