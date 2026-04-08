//===-- ConstantFinder.h - Flag Constants Identification -------*- C++ -*-===//
///
/// \file
/// Module A: Identifies flag constants from enums, macros, and const variables.
/// Simplified version using regex parsing instead of Clang AST.
///
//===----------------------------------------------------------------------===//

#ifndef FLAGREC_CONSTANTFINDER_H
#define FLAGREC_CONSTANTFINDER_H

#include "Types.h"
#include <memory>
#include <set>

namespace flagrec {

/// Configuration for constant finder
struct ConstantFinderConfig {
  int minGroupSize;              // Minimum constants in a group (default: 2)
  bool requireCommonPrefix;      // Require shared prefix for grouping
  std::set<std::string> ignorePrefixes;  // Prefixes to ignore (e.g., "LOG_")

  ConstantFinderConfig()
      : minGroupSize(2), requireCommonPrefix(true) {
    // Common non-flag prefixes to ignore
    ignorePrefixes = {"LOG_", "ERR_", "WARN_", "INFO_", "DEBUG_"};
  }
};

/// Internal: Raw constant before clustering (for API compatibility)
struct RawConstant {
  std::string name;
  int64_t value;
  ConstantType type;
  SourceLocation location;
  std::string enumName;      // For enum constants
  std::string macroContext;  // For macros: header file context

  RawConstant(const std::string &n, int64_t v, ConstantType t,
              const SourceLocation &loc, const std::string &ctx = "")
      : name(n), value(v), type(t), location(loc), enumName(ctx),
        macroContext(ctx) {}
};

/// Forward declaration of internal structure
struct ParsedConstant;

/// Main interface for finding and grouping flag constants
class ConstantFinder {
public:
  ConstantFinder(const ConstantFinderConfig &config = ConstantFinderConfig());

  /// Find constants from a compilation database and source files
  AnalysisResult::Stats findConstants(
      const std::string &compileCommandsPath,
      const std::vector<std::string> &targetFiles,
      std::vector<ConstantGroup> &outGroups);

  /// Alternative: Find constants from a single file with custom compile args
  bool findConstantsInFile(
      const std::string &sourceFile,
      const std::vector<std::string> &compileArgs,
      std::vector<ConstantGroup> &outGroups);

  /// Also extract macro constants from preprocessor (unused in simplified version)
  bool extractMacroConstantsWithCompileInfo(
      const std::string &sourceFile,
      const std::vector<std::string> &compileArgs,
      std::vector<RawConstant> &outMacros);

private:
  ConstantFinderConfig config;

  // Grouping/clustering methods
  void clusterParsedConstants(
      const std::vector<ParsedConstant> &rawConsts,
      std::vector<ConstantGroup> &outGroups);

  void clusterConstants(
      const std::vector<RawConstant> &rawConsts,
      std::vector<ConstantGroup> &outGroups);

  // Extract common prefix from a list of constants
  std::string extractCommonPrefix(const std::vector<ParsedConstant> &consts) const;

  // Check if constants should form a group
  bool shouldGroup(const RawConstant &c1, const RawConstant &c2) const;

  // Group constants by their semantic relationship
  std::vector<std::vector<RawConstant>> groupBySemantics(
      const std::vector<RawConstant> &constants) const;

  // Assign macro constants to groups based on proximity and naming
  void assignMacroGroups(
      std::vector<RawConstant> &macros,
      std::vector<ConstantGroup> &groups) const;
};

} // namespace flagrec

#endif // FLAGREC_CONSTANTFINDER_H
