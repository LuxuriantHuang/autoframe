//===-- FlagRec.h - Main Flag Recognition Interface ---------*- C++ -*-===//
///
/// \file
/// Main interface for the flag variable recognition system.
/// Orchestrates the three main modules: constant finding, variable filtering,
/// and flag identification.
///
//===----------------------------------------------------------------------===//

#ifndef FLAGREC_FLAGREC_H
#define FLAGREC_FLAGREC_H

#include "Types.h"
#include "ConstantFinder.h"
#include "VariableFilter.h"
#include "FlagIdentifier.h"

#include <string>
#include <vector>
#include <memory>

namespace flagrec {

/// Main configuration for the flag recognition pipeline
struct FlagRecConfig {
  // Input paths
  std::string compileCommandsPath;
  std::vector<std::string> targetFiles;
  std::string outputDir;

  // Module-specific configs
  ConstantFinderConfig constantConfig;
  VariableFilterConfig variableConfig;
  FlagIdentifierConfig flagConfig;

  // Global options
  bool verbose;
  bool saveIntermediates;  // Save intermediate results (constants.json, etc.)

  FlagRecConfig()
      : outputDir("./flagrec_output"), verbose(false),
        saveIntermediates(false) {}
};

/// Main orchestrator for flag variable recognition
class FlagRecognizer {
public:
  FlagRecognizer(const FlagRecConfig &config);

  /// Run the complete analysis pipeline
  bool run(AnalysisResult &outResult);

  /// Run analysis and write outputs
  bool runAndWrite(AnalysisResult &outResult);

  /// Run analysis on pre-compiled bitcode file with source directory
  bool runOnBitcode(const std::string &bitcodeFile,
                    const std::string &sourceDir,
                    AnalysisResult &outResult);

  /// Get the current configuration
  const FlagRecConfig& getConfig() const { return config; }

  /// Access individual modules (for advanced usage)
  ConstantFinder& getConstantFinder() { return constantFinder; }
  VariableFilter& getVariableFilter() { return variableFilter; }
  FlagIdentifier& getFlagIdentifier() { return flagIdentifier; }

private:
  FlagRecConfig config;
  ConstantFinder constantFinder;
  VariableFilter variableFilter;
  FlagIdentifier flagIdentifier;

  // Pipeline steps
  bool step1_FindConstants(AnalysisResult::Stats &outStats,
                           std::vector<ConstantGroup> &outGroups);
  bool step2_FilterVariables(AnalysisResult::Stats &outStats,
                             std::vector<VarCandidate> &outCandidates);
  bool step3_IdentifyFlags(
      const std::vector<VarCandidate> &candidates,
      const std::vector<ConstantGroup> &groups,
      std::vector<FlagVariable> &outFlags);

  // Helper methods
  bool compileTargetToBitcode(const std::string &sourceFile,
                              const std::string &bitcodeFile);
  std::string findCompileCommand(const std::string &sourceFile);

  // Output methods
  bool saveConstants(const std::vector<ConstantGroup> &groups);
  bool saveCandidates(const std::vector<VarCandidate> &candidates);
  bool saveResults(const AnalysisResult &result);
};

/// Utility: Parse compile_commands.json
struct CompileCommand {
  std::string directory;
  std::string command;
  std::string file;
};

class CompileCommandsParser {
public:
  /// Parse compile_commands.json file
  static bool parse(const std::string &path,
                    std::vector<CompileCommand> &outCommands);

  /// Find compile command for a specific source file
  static const CompileCommand*
  findCommand(const std::vector<CompileCommand> &commands,
              const std::string &sourceFile);

  /// Extract compiler arguments from command string
  static std::vector<std::string>
  extractArgs(const CompileCommand &cmd);
};

} // namespace flagrec

#endif // FLAGREC_FLAGREC_H
