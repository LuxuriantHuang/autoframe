//===-- FlagIdentifier.h - Flag Variable Identification -------*- C++ -*-===//
///
/// \file
/// Module C: Matches variable candidates with constant groups to identify
/// flag variables. Collects assignment and check points.
///
//===----------------------------------------------------------------------===//

#ifndef FLAGREC_FLAGIDENTIFIER_H
#define FLAGREC_FLAGIDENTIFIER_H

#include "Types.h"
#include "VariableFilter.h"
#include <llvm/IR/Module.h>
#include <llvm/IR/InstVisitor.h>
#include <map>
#include <set>

namespace flagrec {

/// Configuration for flag identification
struct FlagIdentifierConfig {
  double minConfidence;         // Minimum confidence to report (default: 0.5)
  bool requireMultipleAssigns;  // Require multiple different constant assigns
  bool trackSwitchCases;        // Include switch statements as checks

  FlagIdentifierConfig()
      : minConfidence(0.2), requireMultipleAssigns(false),
        trackSwitchCases(true) {}
};

/// Analysis context for a single variable
struct VarAnalysisContext {
  VarCandidate candidate;
  std::string matchedGroupId;      // Matched constant group
  std::vector<AssignmentPoint> assignments;
  std::vector<CheckPoint> checks;
  double confidence;

  VarAnalysisContext() : confidence(0.0) {}
};

/// Statistics for flag identification
struct FlagIdentifierStats {
  int totalCandidates;
  int matchedToGroups;
  int lowConfidenceFiltered;
  int finalFlagVars;

  FlagIdentifierStats() : totalCandidates(0), matchedToGroups(0),
                          lowConfidenceFiltered(0), finalFlagVars(0) {}
};

/// Main flag identifier that matches variables with constants
class FlagIdentifier {
public:
  FlagIdentifier(const FlagIdentifierConfig &config = FlagIdentifierConfig());

  /// Identify flag variables from candidates and constant groups
  bool identifyFlags(
      const std::vector<VarCandidate> &candidates,
      const std::vector<ConstantGroup> &groups,
      std::vector<FlagVariable> &outFlags);

  /// Alternative: Analyze LLVM IR directly
  bool identifyFlagsFromIR(
      llvm::Module *module,
      const std::vector<ConstantGroup> &groups,
      const std::vector<VarCandidate> &candidates,
      std::vector<FlagVariable> &outFlags);

  /// Calculate confidence score for a flag variable
  double calculateConfidence(
      const VarAnalysisContext &ctx,
      const ConstantGroup *group = nullptr) const;

  FlagIdentifierStats getStats() const { return stats; }

private:
  FlagIdentifierConfig config;
  FlagIdentifierStats stats;

  // Match a candidate variable to a constant group
  std::string matchToGroup(
      const VarCandidate &candidate,
      const std::vector<ConstantGroup> &groups) const;

  // Check if variable's assigned constants match a group
  double calculateGroupMatch(
      const std::set<int64_t> &assignedConsts,
      const ConstantGroup &group) const;

  // Collect assignment points for a variable
  void collectAssignments(
      llvm::Value *variable,
      llvm::Function *func,
      const std::set<int64_t> &groupValues,
      std::vector<AssignmentPoint> &outAssignments);

  // Collect check points for a variable
  void collectChecks(
      llvm::Value *variable,
      llvm::Function *func,
      const std::set<int64_t> &groupValues,
      std::vector<CheckPoint> &outChecks);

  // Analyze a single variable
  void analyzeVariable(
      llvm::Value *variable,
      const VarCandidate &candidate,
      const std::vector<ConstantGroup> &groups,
      VarAnalysisContext &outContext);

  // Build CFG and find all uses of variable
  void findAllUses(
      llvm::Value *variable,
      llvm::Function *func,
      std::vector<llvm::Use*> &outUses);

  // Get source location from instruction
  SourceLocation getSourceLocation(llvm::Instruction *inst) const;
};

/// Visitor for collecting assignments and checks
class FlagUsageVisitor : public llvm::InstVisitor<FlagUsageVisitor> {
public:
  FlagUsageVisitor(const std::set<int64_t> &groupVals,
                   const std::string &varName,
                   llvm::Value *targetVar)
      : groupValues(groupVals), variableName(varName), targetVariable(targetVar) {}

  void visitStoreInst(llvm::StoreInst &si);
  void visitICmpInst(llvm::ICmpInst &ici);
  void visitSwitchInst(llvm::SwitchInst &si);
  void visitBinaryOperator(llvm::BinaryOperator &bo);

  const std::vector<AssignmentPoint>& getAssignments() const {
    return assignments;
  }

  const std::vector<CheckPoint>& getChecks() const {
    return checks;
  }

private:
  const std::set<int64_t> &groupValues;
  std::string variableName;
  llvm::Value *targetVariable;
  std::vector<AssignmentPoint> assignments;
  std::vector<CheckPoint> checks;

  SourceLocation getSourceLocation(llvm::Instruction *inst) const;
};

/// Utility: Generate JSON output from analysis results
class JSONReporter {
public:
  /// Convert analysis result to JSON string
  static std::string generateJSON(const AnalysisResult &result);

  /// Write analysis result to file
  static bool writeToFile(const AnalysisResult &result,
                          const std::string &outputPath);

private:
  // Helper methods for JSON generation
  static std::string constantGroupToJSON(const ConstantGroup &group);
  static std::string flagVariableToJSON(const FlagVariable &flag);
  static std::string escapeJSON(const std::string &str);
};

/// Utility: Generate markdown report
class MarkdownReporter {
public:
  /// Generate analysis report
  static std::string generateReport(const AnalysisResult &result);

  /// Write report to file
  static bool writeToFile(const AnalysisResult &result,
                          const std::string &outputPath);

private:
  static std::string generateStats(const AnalysisResult::Stats &stats, size_t flagCount);
  static std::string generateFlagDetails(const std::vector<FlagVariable> &flags);
};

} // namespace flagrec

#endif // FLAGREC_FLAGIDENTIFIER_H
