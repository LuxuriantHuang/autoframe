//===-- FlagRec.cpp - Main Orchestrator Implementation -----*- C++ -*-===//
///
/// \file
/// Implementation of the main FlagRecognizer orchestrator
///
//===----------------------------------------------------------------------===//

#include "FlagRec.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>
#include <sstream>

using namespace llvm;

namespace flagrec {

//===----------------------------------------------------------------------===//
// FlagRecognizer Implementation
//===----------------------------------------------------------------------===//

FlagRecognizer::FlagRecognizer(const FlagRecConfig &cfg)
    : config(cfg),
      constantFinder(cfg.constantConfig),
      variableFilter(cfg.variableConfig),
      flagIdentifier(cfg.flagConfig) {}

bool FlagRecognizer::run(AnalysisResult &outResult) {
  outResult = AnalysisResult();

  // Step 1: Find constants
  std::vector<ConstantGroup> groups;
  if (!step1_FindConstants(outResult.stats, groups)) {
    llvm::errs() << "Failed to find constants\n";
    return false;
  }
  outResult.constantGroups = groups;

  // Step 2: Filter variables
  std::vector<VarCandidate> candidates;
  if (!step2_FilterVariables(outResult.stats, candidates)) {
    llvm::errs() << "Failed to filter variables\n";
    return false;
  }

  // Step 3: Identify flags
  std::vector<FlagVariable> flags;
  if (!step3_IdentifyFlags(candidates, groups, flags)) {
    llvm::errs() << "Failed to identify flags\n";
    return false;
  }
  outResult.flagVariables = flags;

  return true;
}

bool FlagRecognizer::runAndWrite(AnalysisResult &outResult) {
  if (!run(outResult)) {
    return false;
  }

  // Create output directory
  if (!sys::fs::exists(config.outputDir)) {
    if (auto ec = sys::fs::create_directories(config.outputDir)) {
      llvm::errs() << "Failed to create output directory: " << ec.message() << "\n";
      return false;
    }
  }

  // Save intermediate results
  if (config.saveIntermediates) {
    saveConstants(outResult.constantGroups);
    saveCandidates({}); // Would need to expose candidates
  }

  // Save final results
  return saveResults(outResult);
}

bool FlagRecognizer::step1_FindConstants(AnalysisResult::Stats &outStats,
                                         std::vector<ConstantGroup> &outGroups) {
  if (config.verbose) {
    llvm::outs() << "Step 1: Finding flag constants...\n";
  }

  outStats = constantFinder.findConstants(
      config.compileCommandsPath,
      config.targetFiles,
      outGroups);

  if (config.verbose) {
    llvm::outs() << "  Found " << outStats.totalConstants << " constants in "
                 << outStats.totalGroups << " groups\n";
  }

  return !outGroups.empty();
}

bool FlagRecognizer::step2_FilterVariables(AnalysisResult::Stats &outStats,
                                           std::vector<VarCandidate> &outCandidates) {
  if (config.verbose) {
    llvm::outs() << "Step 2: Filtering variable candidates...\n";
  }

  // For each target file, compile to bitcode and analyze
  for (const auto &sourceFile : config.targetFiles) {
    std::string bitcodePath = config.outputDir + "/" +
                             sys::path::stem(sourceFile).str() + ".bc";

    if (!compileTargetToBitcode(sourceFile, bitcodePath)) {
      llvm::errs() << "Failed to compile " << sourceFile << " to bitcode\n";
      continue;
    }

    std::vector<VarCandidate> fileCandidates;
    if (variableFilter.analyzeBitcodeFile(bitcodePath, fileCandidates)) {
      outCandidates.insert(outCandidates.end(),
                          fileCandidates.begin(),
                          fileCandidates.end());
    }
  }

  // Get stats and copy to output
  FilterStats filterStats = variableFilter.getStats();
  outStats.totalVariables = filterStats.totalVariables;
  outStats.filteredInputVars = filterStats.filteredInputVars;
  outStats.filteredArithmeticVars = filterStats.filteredArithmeticVars;

  if (config.verbose) {
    llvm::outs() << "  Total variables: " << filterStats.totalVariables << "\n";
    llvm::outs() << "  Filtered (input): " << filterStats.filteredInputVars << "\n";
    llvm::outs() << "  Filtered (arithmetic): " << filterStats.filteredArithmeticVars << "\n";
    llvm::outs() << "  Remaining candidates: " << filterStats.remainingCandidates << "\n";
  }

  return !outCandidates.empty();
}

bool FlagRecognizer::step3_IdentifyFlags(
    const std::vector<VarCandidate> &candidates,
    const std::vector<ConstantGroup> &groups,
    std::vector<FlagVariable> &outFlags) {

  if (config.verbose) {
    llvm::outs() << "Step 3: Identifying flag variables...\n";
  }

  if (!flagIdentifier.identifyFlags(candidates, groups, outFlags)) {
    return false;
  }

  if (config.verbose) {
    auto stats = flagIdentifier.getStats();
    llvm::outs() << "  Total candidates: " << stats.totalCandidates << "\n";
    llvm::outs() << "  Matched to groups: " << stats.matchedToGroups << "\n";
    llvm::outs() << "  Low confidence filtered: " << stats.lowConfidenceFiltered << "\n";
    llvm::outs() << "  Final flag variables: " << stats.finalFlagVars << "\n";
  }

  return true;
}

bool FlagRecognizer::compileTargetToBitcode(const std::string &sourceFile,
                                            const std::string &bitcodeFile) {
  // Find compile command
  std::string compileCmd = findCompileCommand(sourceFile);
  if (compileCmd.empty()) {
    // Try to generate a basic command
    compileCmd = "clang -emit-llvm -c -o " + bitcodeFile + " " + sourceFile;
  } else {
    // Modify to emit LLVM bitcode
    // Replace -c with -emit-llvm -c
    size_t pos = compileCmd.find(" -c ");
    if (pos != std::string::npos) {
      compileCmd.replace(pos, 3, " -emit-llvm -c ");
    }

    // Replace output
    pos = compileCmd.find(" -o ");
    if (pos != std::string::npos) {
      size_t endPos = compileCmd.find(' ', pos + 4);
      if (endPos == std::string::npos) {
        compileCmd = compileCmd.substr(0, pos + 4) + bitcodeFile;
      } else {
        compileCmd = compileCmd.substr(0, pos + 4) + bitcodeFile +
                     compileCmd.substr(endPos);
      }
    } else {
      compileCmd += " -o " + bitcodeFile;
    }
  }

  if (config.verbose) {
    llvm::outs() << "  Compiling: " << compileCmd << "\n";
  }

  // Execute compile command
  int result = system(compileCmd.c_str());
  return result == 0;
}

std::string FlagRecognizer::findCompileCommand(const std::string &sourceFile) {
  // Try to load compile_commands.json
  std::string jsonPath = config.compileCommandsPath + "/compile_commands.json";
  std::vector<CompileCommand> commands;

  if (!CompileCommandsParser::parse(jsonPath, commands)) {
    return "";
  }

  auto cmd = CompileCommandsParser::findCommand(commands, sourceFile);
  if (cmd != nullptr) {
    return cmd->command;
  }

  return "";
}

bool FlagRecognizer::saveConstants(const std::vector<ConstantGroup> &groups) {
  std::string path = config.outputDir + "/constants.json";
  std::ofstream file(path);

  if (!file.is_open()) {
    return false;
  }

  // Simple JSON output
  file << "{\n  \"groups\": [\n";
  for (size_t i = 0; i < groups.size(); ++i) {
    file << "    {\n";
    file << "      \"id\": \"" << groups[i].id << "\",\n";
    file << "      \"prefix\": \"" << groups[i].commonPrefix << "\",\n";
    file << "      \"constants\": [\n";
    for (size_t j = 0; j < groups[i].constants.size(); ++j) {
      const auto &c = groups[i].constants[j];
      file << "        {\"name\": \"" << c.name << "\", \"value\": " << c.value << "}";
      if (j < groups[i].constants.size() - 1) file << ",";
      file << "\n";
    }
    file << "      ]\n";
    file << "    }";
    if (i < groups.size() - 1) file << ",";
    file << "\n";
  }
  file << "  ]\n}\n";

  file.close();
  return true;
}

bool FlagRecognizer::saveCandidates(const std::vector<VarCandidate> &candidates) {
  std::string path = config.outputDir + "/candidates.json";
  std::ofstream file(path);

  if (!file.is_open()) {
    return false;
  }

  file << "{\n  \"candidates\": [\n";
  for (size_t i = 0; i < candidates.size(); ++i) {
    const auto &c = candidates[i];
    file << "    {\n";
    file << "      \"name\": \"" << c.name << "\",\n";
    file << "      \"type\": \"" << c.typeName << "\",\n";
    file << "      \"function\": \"" << c.function << "\",\n";
    file << "      \"isTainted\": " << (c.isTainted ? "true" : "false") << ",\n";
    file << "      \"isArithmetic\": " << (c.isArithmetic ? "true" : "false") << ",\n";
    file << "      \"score\": " << c.calculateScore() << "\n";
    file << "    }";
    if (i < candidates.size() - 1) file << ",";
    file << "\n";
  }
  file << "  ]\n}\n";

  file.close();
  return true;
}

bool FlagRecognizer::saveResults(const AnalysisResult &result) {
  // Save JSON
  std::string jsonPath = config.outputDir + "/flags.json";
  if (!JSONReporter::writeToFile(result, jsonPath)) {
    llvm::errs() << "Failed to write JSON output\n";
    return false;
  }

  // Save Markdown report
  std::string reportPath = config.outputDir + "/report.md";
  if (!MarkdownReporter::writeToFile(result, reportPath)) {
    llvm::errs() << "Failed to write report\n";
    return false;
  }

  if (config.verbose) {
    llvm::outs() << "\nResults written to:\n";
    llvm::outs() << "  " << jsonPath << "\n";
    llvm::outs() << "  " << reportPath << "\n";
  }

  return true;
}

bool FlagRecognizer::runOnBitcode(const std::string &bitcodeFile,
                                  const std::string &sourceDir,
                                  AnalysisResult &outResult) {
  outResult = AnalysisResult();

  if (config.verbose) {
    llvm::outs() << "Running analysis on pre-compiled bitcode:\n";
    llvm::outs() << "  Bitcode: " << bitcodeFile << "\n";
    llvm::outs() << "  Source dir: " << sourceDir << "\n\n";
  }

  // Step 1: Find constants from source directory
  if (config.verbose) {
    llvm::outs() << "Step 1: Finding flag constants from source files...\n";
  }

  // Find all .c and .h files in source directory
  std::vector<std::string> sourceFiles;
  std::vector<std::string> headerFiles;

  // Use glob to find source files
  std::error_code ec;
  for (sys::fs::directory_iterator it(sourceDir, ec), end; it != end && !ec; it.increment(ec)) {
    auto path = it->path();
    std::string ext = sys::path::extension(path).str();
    if (ext == ".c" || ext == ".cpp" || ext == ".cc") {
      sourceFiles.push_back(path);
    } else if (ext == ".h" || ext == ".hpp") {
      headerFiles.push_back(path);
    }
  }

  if (config.verbose) {
    llvm::outs() << "  Found " << sourceFiles.size() << " source files\n";
    llvm::outs() << "  Found " << headerFiles.size() << " header files\n";
  }

  // Also search recursively in subdirectories
  std::vector<std::string> allFiles = sourceFiles;
  allFiles.insert(allFiles.end(), headerFiles.begin(), headerFiles.end());

  std::vector<ConstantGroup> groups;
  outResult.stats = constantFinder.findConstants("", allFiles, groups);

  if (config.verbose) {
    llvm::outs() << "  Found " << outResult.stats.totalConstants << " constants in "
                 << outResult.stats.totalGroups << " groups\n\n";
  }

  outResult.constantGroups = groups;

  // Step 2: Analyze variables from bitcode
  if (config.verbose) {
    llvm::outs() << "Step 2: Analyzing variables from bitcode...\n";
  }

  std::vector<VarCandidate> candidates;
  if (!variableFilter.analyzeBitcodeFile(bitcodeFile, candidates)) {
    llvm::errs() << "Failed to analyze bitcode file\n";
    return false;
  }

  FilterStats filterStats = variableFilter.getStats();
  outResult.stats.totalVariables = filterStats.totalVariables;
  outResult.stats.filteredInputVars = filterStats.filteredInputVars;
  outResult.stats.filteredArithmeticVars = filterStats.filteredArithmeticVars;

  if (config.verbose) {
    llvm::outs() << "  Total variables: " << filterStats.totalVariables << "\n";
    llvm::outs() << "  Remaining candidates: " << filterStats.remainingCandidates << "\n\n";
  }

  // Step 3: Identify flags
  if (config.verbose) {
    llvm::outs() << "Step 3: Identifying flag variables...\n";
  }

  std::vector<FlagVariable> flags;
  if (!flagIdentifier.identifyFlags(candidates, groups, flags)) {
    llvm::errs() << "Failed to identify flags\n";
    return false;
  }

  outResult.flagVariables = flags;

  if (config.verbose) {
    auto stats = flagIdentifier.getStats();
    llvm::outs() << "  Total candidates: " << stats.totalCandidates << "\n";
    llvm::outs() << "  Matched to groups: " << stats.matchedToGroups << "\n";
    llvm::outs() << "  Low confidence filtered: " << stats.lowConfidenceFiltered << "\n";
    llvm::outs() << "  Final flag variables: " << stats.finalFlagVars << "\n";
  }

  return true;
}

//===----------------------------------------------------------------------===//
// CompileCommandsParser Implementation
//===----------------------------------------------------------------------===//

bool CompileCommandsParser::parse(const std::string &path,
                                  std::vector<CompileCommand> &outCommands) {
  std::ifstream file(path);
  if (!file.is_open()) {
    return false;
  }

  // Simple JSON parsing for compile_commands.json
  std::string line;
  bool inEntries = false;

  while (std::getline(file, line)) {
    // Skip whitespace
    size_t start = line.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) continue;

    // Look for "file" and "command" entries
    if (line.find("\"file\":") != std::string::npos) {
      CompileCommand cmd;
      size_t colon = line.find(":");
      size_t quote1 = line.find("\"", colon + 1);
      size_t quote2 = line.find("\"", quote1 + 1);
      if (quote1 != std::string::npos && quote2 != std::string::npos) {
        cmd.file = line.substr(quote1 + 1, quote2 - quote1 - 1);

        // Read next line for command
        while (std::getline(file, line)) {
          if (line.find("\"command\":") != std::string::npos) {
            colon = line.find(":");
            quote1 = line.find("\"", colon + 1);
            quote2 = line.rfind("\"");
            if (quote1 != std::string::npos && quote2 != std::string::npos &&
                quote2 > quote1 + 1) {
              cmd.command = line.substr(quote1 + 1, quote2 - quote1 - 1);
              outCommands.push_back(cmd);
            }
            break;
          }
        }
      }
    }
  }

  file.close();
  return !outCommands.empty();
}

const CompileCommand*
CompileCommandsParser::findCommand(const std::vector<CompileCommand> &commands,
                                   const std::string &sourceFile) {
  for (const auto &cmd : commands) {
    if (cmd.file == sourceFile) {
      return &cmd;
    }
  }

  // Try basename match
  std::string basename = sys::path::filename(sourceFile).str();
  for (const auto &cmd : commands) {
    if (sys::path::filename(cmd.file).str() == basename) {
      return &cmd;
    }
  }

  return nullptr;
}

std::vector<std::string>
CompileCommandsParser::extractArgs(const CompileCommand &cmd) {
  std::vector<std::string> args;

  // Simple shell-like tokenization
  std::string arg;
  bool inQuote = false;

  for (char c : cmd.command) {
    if (c == '"') {
      inQuote = !inQuote;
    } else if (std::isspace(c) && !inQuote) {
      if (!arg.empty()) {
        args.push_back(arg);
        arg.clear();
      }
    } else {
      arg += c;
    }
  }

  if (!arg.empty()) {
    args.push_back(arg);
  }

  return args;
}

} // namespace flagrec
