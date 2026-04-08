//===-- VariableFilter.h - Flag Variable Candidate Filtering ----*- C++ -*-===//
///
/// \file
/// Module B: Filters variable candidates to identify potential flag variables.
/// Excludes: (1) Input-reachable variables (tainted), (2) Arithmetic variables.
///
//===----------------------------------------------------------------------===//

#ifndef FLAGREC_VARIABLEFILTER_H
#define FLAGREC_VARIABLEFILTER_H

#include "Types.h"
#include "ASTParser.h"
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <map>
#include <memory>
#include <set>

namespace flagrec {

/// Configuration for variable filtering
struct VariableFilterConfig {
  bool enableTaintAnalysis;
  bool enableArithmeticFilter;
  bool conservativeMode;  // If true, keep more candidates (fewer false negatives)
  bool verbose;            // Print debug information

  // Predefined input/API functions that taint variables
  std::set<std::string> taintSources;

  VariableFilterConfig()
      : enableTaintAnalysis(true), enableArithmeticFilter(true),
        conservativeMode(false), verbose(false) {
    // Standard input functions
    taintSources = {
      "read", "pread", "readv", "fread", "fgets", "getline", "getchar",
      "fgetc", "getc", "recv", "recvfrom", "recvmsg", "readlink",
      "scanf", "fscanf", "sscanf", "getc", "getw",
      "SDL_PollEvent", "SDL_WaitEvent",
      "curl_easy_perform"
    };
  }
};

/// Information about a variable candidate
struct VarCandidate {
  std::string name;              // Variable name
  llvm::Value *value;            // LLVM Value pointer
  std::string typeName;          // Type name
  std::string function;          // Containing function
  SourceLocation location;       // Source location
  bool isGlobal;                 // Is global variable

  // Analysis flags
  bool isTainted;                // Reached by input
  bool isArithmetic;             // Used in arithmetic operations
  bool hasBitOps;                // Used in bitwise operations
  bool hasComparisons;           // Used in comparisons (good sign)
  bool hasStoresFromConst;       // Stored from constants (good sign)
  bool isLoopVariable;           // Used as loop counter (i, j, k, row, col, etc.)

  // Constants assigned to this variable
  std::set<int64_t> assignedConstants;

  // Struct member information (NEW)
  bool isStructMember;           // Is this a struct field access
  std::string basePointerName;   // Base pointer name (e.g., "png_ptr")
  std::string fieldName;         // Field name (e.g., "transformations")
  std::string structTypeName;    // Struct type name (e.g., "png_struct_def")
  int fieldIndex;                // LLVM GEP field index
  bool hasBitwiseOrStore;        // |= pattern detected (strong flag indicator)
  std::vector<SourceLocation> usageLocations;  // All usage locations for struct members

  VarCandidate() : value(nullptr), isGlobal(false), isTainted(false),
                   isArithmetic(false), hasBitOps(false),
                   hasComparisons(false), hasStoresFromConst(false),
                   isLoopVariable(false), isStructMember(false),
                   fieldIndex(-1), hasBitwiseOrStore(false) {}

  /// Calculate a "flag-likeness" score
  double calculateScore() const {
    if (isTainted) return 0.0;
    if (isArithmetic) return 0.0;
    if (isLoopVariable) return 0.0;  // Loop variables are not flag variables

    double score = 0.0;
    if (hasStoresFromConst) score += 0.4;
    if (hasComparisons) score += 0.3;
    if (hasBitOps) score += 0.2;
    if (!assignedConstants.empty()) score += 0.1;

    // Bonus for struct members with flag-like names
    if (isStructMember) {
      // Check for flag-like field names
      std::string lowerName = fieldName;
      std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
      if (lowerName.find("mode") != std::string::npos ||
          lowerName.find("flag") != std::string::npos ||
          lowerName.find("state") != std::string::npos ||
          lowerName.find("transform") != std::string::npos) {
        score += 0.15;
      }
      // Extra bonus for |= pattern
      if (hasBitwiseOrStore) score += 0.2;
    }

    return std::min(score, 1.0);
  }

  /// Get full display name (including struct access if applicable)
  std::string getDisplayName() const {
    if (isStructMember && !basePointerName.empty() && !fieldName.empty()) {
      return basePointerName + "->" + fieldName;
    }
    return name;
  }
};

/// Statistics for variable filtering
struct FilterStats {
  int totalVariables;
  int filteredInputVars;
  int filteredArithmeticVars;
  int filteredLoopVars;      // Loop counter variables filtered
  int remainingCandidates;

  FilterStats() : totalVariables(0), filteredInputVars(0),
                  filteredArithmeticVars(0), filteredLoopVars(0),
                  remainingCandidates(0) {}
};

/// LLVM IR analysis pass to filter variable candidates
class VariableFilter {
public:
  VariableFilter(const VariableFilterConfig &config = VariableFilterConfig());

  /// Analyze a module (from LLVM IR)
  bool analyzeModule(
      llvm::Module *module,
      std::vector<VarCandidate> &outCandidates);

  /// Analyze a single bitcode file
  bool analyzeBitcodeFile(
      const std::string &bitcodeFile,
      std::vector<VarCandidate> &outCandidates);

  /// Analyze with additional AST information from source files
  bool analyzeBitcodeWithAST(
      const std::string &bitcodeFile,
      const std::string &sourceDir,
      std::vector<VarCandidate> &outCandidates);

  /// Get filtered candidates (passing all filters)
  std::vector<VarCandidate> getFilteredCandidates() const;

  /// Get statistics
  FilterStats getStats() const;

private:
  VariableFilterConfig config;
  FilterStats stats;
  std::vector<VarCandidate> candidates;

  // AST parser for struct field information
  std::unique_ptr<ASTParser> astParser;
  std::vector<StructInfo> parsedStructs;

  // Taint analysis
  void performTaintAnalysis(llvm::Module *module);

  // Mark variables as tainted based on data flow
  void propagateTaint(llvm::Function *func,
                      std::set<llvm::Value*> &taintedValues);

  // Arithmetic analysis
  void findArithmeticVariables(llvm::Module *module);

  // Collect all variables (globals + locals)
  void collectVariables(llvm::Module *module);

  // Collect struct member variables (NEW)
  void collectStructMembers(llvm::Module *module);

  // Analyze variable usage patterns
  void analyzeVariableUsage(llvm::Module *module, std::map<llvm::Value*, size_t> &valueToCandidate);

  // Check if a value is a constant
  bool isConstantInt(llvm::Value *v, int64_t &outValue) const;

  // Check if instruction is arithmetic (excluding bit ops)
  bool isArithmeticOp(llvm::Instruction *inst) const;

  // Check if instruction is bitwise operation
  bool isBitOp(llvm::Instruction *inst) const;

  // Check if function is a taint source
  bool isTaintSource(llvm::Function *func) const;

  // Get source location from LLVM value
  SourceLocation getSourceLocation(llvm::Value *v) const;

  // Helper method to mark variable as arithmetic
  void markVariableAsArithmetic(llvm::Value *v, const std::string &funcName);

  // Check if field name is flag-like (NEW)
  bool isFlagLikeFieldName(const std::string &fieldName) const;

  // Check if variable name is a loop counter (NEW)
  bool isLoopCounterName(const std::string &varName) const;

  // Get field name from GEP instruction (NEW)
  std::string getFieldNameFromGEP(llvm::GetElementPtrInst *gep,
                                   std::string &structTypeName,
                                   int &fieldIndex) const;

  // Track struct member usage (NEW)
  void trackStructMemberUsage(llvm::GetElementPtrInst *gep, VarCandidate &cand);

  // Find or create VarCandidate for a struct member (NEW)
  VarCandidate* findOrCreateStructMember(llvm::GetElementPtrInst *gep);
};

/// Helper visitor for analyzing variable usage
class VarUsageVisitor : public llvm::InstVisitor<VarUsageVisitor> {
public:
  VarUsageVisitor(VarCandidate &cand) : candidate(cand) {}

  void visitLoadInst(llvm::LoadInst &li);
  void visitStoreInst(llvm::StoreInst &si);
  void visitICmpInst(llvm::ICmpInst &ici);
  void visitBinaryOperator(llvm::BinaryOperator &bo);

private:
  VarCandidate &candidate;
};

} // namespace flagrec

#endif // FLAGREC_VARIABLEFILTER_H
