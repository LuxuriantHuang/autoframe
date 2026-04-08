//===-- main.cpp - Flag Recognition CLI Tool ---------------*- C++ -*-===//
///
/// \file
/// Command-line interface for the flag variable recognition tool.
///
//===----------------------------------------------------------------------===//

#include "FlagRec.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdlib>

using namespace llvm;
using namespace flagrec;

// Command line options
static cl::opt<std::string> CompileCommandsPath(
    "compile_commands", cl::init(""),
    cl::desc("Path to directory containing compile_commands.json or build directory"));

static cl::opt<std::string> TargetFiles(
    "targets", cl::init(""),
    cl::desc("Comma-separated list of source files to analyze (supports wildcards)"));

static cl::opt<std::string> BitcodeFile(
    "bitcode", cl::init(""),
    cl::desc("Path to pre-compiled .bc file for analysis"));

static cl::opt<std::string> SourceDir(
    "source-dir", cl::init(""),
    cl::desc("Path to source directory for constant extraction (use with --bitcode)"));

static cl::opt<std::string> OutputDir(
    "out", cl::init("./flagrec_output"),
    cl::desc("Output directory for results"));

static cl::opt<bool> Verbose(
    "verbose", cl::init(false),
    cl::desc("Enable verbose output"));

static cl::opt<bool> SaveIntermediates(
    "save-intermediates", cl::init(false),
    cl::desc("Save intermediate analysis results"));

static cl::opt<double> MinConfidence(
    "min-confidence", cl::init(0.5),
    cl::desc("Minimum confidence score for flag variables (0.0-1.0)"));

static cl::opt<int> MinGroupSize(
    "min-group-size", cl::init(2),
    cl::desc("Minimum number of constants in a group"));

static cl::opt<bool> ConservativeMode(
    "conservative", cl::init(false),
    cl::desc("Enable conservative mode (fewer false negatives)"));

static cl::opt<bool> EnableTaintAnalysis(
    "enable-taint", cl::init(true),
    cl::desc("Enable taint analysis to filter input variables"));

static cl::opt<std::string> IgnorePrefixes(
    "ignore-prefixes", cl::init("LOG_,ERR_,WARN_,INFO_,DEBUG_"),
    cl::desc("Comma-separated list of constant prefixes to ignore"));

void printVersion(llvm::raw_ostream &os) {
  os << "flagrec - Flag Variable Recognition Tool v1.0\n";
  os << "Based on ALGERNON paper design\n";
  os << "Using LLVM " << LLVM_VERSION_STRING << "\n";
}

void printUsage() {
  printVersion(llvm::outs());
  outs() << "\nUsage:\n";
  outs() << "  flagrec --compile_commands <path> --targets <files> [options]\n";
  outs() << "  flagrec --bitcode <file.bc> --source-dir <dir> [options]\n\n";
  outs() << "Required (mode 1 - source analysis):\n";
  outs() << "  --compile_commands <path>   Path to build directory with compile_commands.json\n";
  outs() << "  --targets <files>           Comma-separated source files to analyze\n\n";
  outs() << "Required (mode 2 - bitcode analysis):\n";
  outs() << "  --bitcode <file.bc>         Path to pre-compiled bitcode file\n";
  outs() << "  --source-dir <dir>          Path to source directory for constant extraction\n\n";
  outs() << "Options:\n";
  outs() << "  --out <dir>                 Output directory (default: ./flagrec_output)\n";
  outs() << "  --verbose                   Enable verbose output\n";
  outs() << "  --min-confidence <val>      Minimum confidence (default: 0.5)\n";
  outs() << "  --min-group-size <n>        Minimum constants per group (default: 2)\n";
  outs() << "  --conservative              Enable conservative mode\n";
  outs() << "  --ignore-prefixes <str>     Prefixes to ignore (default: LOG_,ERR_,WARN_,INFO_,DEBUG_)\n";
  outs() << "  --save-intermediates        Save intermediate results\n";
}

std::vector<std::string> splitString(const std::string &str, char delimiter) {
  std::vector<std::string> result;
  std::stringstream ss(str);
  std::string item;

  while (std::getline(ss, item, delimiter)) {
    // Trim whitespace
    size_t start = item.find_first_not_of(" \t");
    size_t end = item.find_last_not_of(" \t");
    if (start != std::string::npos) {
      result.push_back(item.substr(start, end - start + 1));
    }
  }

  return result;
}

std::set<std::string> splitToSet(const std::string &str, char delimiter) {
  std::vector<std::string> vec = splitString(str, delimiter);
  return std::set<std::string>(vec.begin(), vec.end());
}

int main(int argc, char **argv) {
  cl::SetVersionPrinter(printVersion);

  // Parse command line
  cl::ParseCommandLineOptions(argc, argv,
    "Flag Variable Recognition Tool\nIdentifies flag variables in C/C++ code\n");

  if (argc < 2) {
    printUsage();
    return 1;
  }

  outs() << "========================================\n";
  outs() << "Flag Variable Recognition Tool\n";
  outs() << "========================================\n\n";

  // Determine which mode to run
  bool useBitcodeMode = !BitcodeFile.empty();
  bool useSourceMode = !CompileCommandsPath.empty() && !TargetFiles.empty();

  if (!useBitcodeMode && !useSourceMode) {
    errs() << "Error: Must specify either:\n";
    errs() << "  1. --compile_commands and --targets for source analysis, or\n";
    errs() << "  2. --bitcode and --source-dir for bitcode analysis\n";
    return 1;
  }

  if (useBitcodeMode) {
    // Bitcode mode
    if (SourceDir.empty()) {
      errs() << "Error: --source-dir is required when using --bitcode\n";
      return 1;
    }

    if (!sys::fs::exists(BitcodeFile)) {
      errs() << "Error: Bitcode file does not exist: " << BitcodeFile << "\n";
      return 1;
    }

    if (!sys::fs::exists(SourceDir)) {
      errs() << "Error: Source directory does not exist: " << SourceDir << "\n";
      return 1;
    }

    outs() << "Bitcode analysis mode:\n";
    outs() << "  Bitcode: " << BitcodeFile << "\n";
    outs() << "  Source dir: " << SourceDir << "\n\n";

    // Configure the analyzer
    FlagRecConfig config;
    config.outputDir = OutputDir;
    config.verbose = Verbose;
    config.saveIntermediates = SaveIntermediates;
    config.constantConfig.minGroupSize = MinGroupSize;
    config.constantConfig.ignorePrefixes = splitToSet(IgnorePrefixes, ',');
    config.variableConfig.enableTaintAnalysis = EnableTaintAnalysis;
    config.variableConfig.conservativeMode = ConservativeMode;
    config.flagConfig.minConfidence = MinConfidence;

    FlagRecognizer recognizer(config);

    outs() << "Starting analysis...\n\n";

    AnalysisResult result;
    if (!recognizer.runOnBitcode(BitcodeFile, SourceDir, result)) {
      errs() << "\nAnalysis failed!\n";
      return 1;
    }

    // Create output directory and save results
    if (!sys::fs::exists(OutputDir)) {
      if (auto ec = sys::fs::create_directories(OutputDir)) {
        errs() << "Failed to create output directory: " << ec.message() << "\n";
        return 1;
      }
    }

    if (!JSONReporter::writeToFile(result, OutputDir + "/flags.json")) {
      errs() << "Failed to write JSON output\n";
      return 1;
    }

    if (!MarkdownReporter::writeToFile(result, OutputDir + "/report.md")) {
      errs() << "Failed to write report\n";
      return 1;
    }

    // Print summary
    outs() << "\n========================================\n";
    outs() << "Analysis Complete\n";
    outs() << "========================================\n\n";

    outs() << "Summary:\n";
    outs() << "  Constants found: " << result.stats.totalConstants << "\n";
    outs() << "  Constant groups: " << result.stats.totalGroups << "\n";
    outs() << "  Variables analyzed: " << result.stats.totalVariables << "\n";
    outs() << "  Flag variables identified: "
           << result.flagVariables.size() << "\n\n";

    if (!result.flagVariables.empty()) {
      outs() << "Top Flag Variables:\n";
      for (const auto &flag : result.flagVariables) {
        outs() << "  - " << flag.name << " ("
               << (flag.confidence * 100) << "% confidence)\n";
        outs() << "    Location: " << flag.location.toString() << "\n";
        if (!flag.groupId.empty()) {
          outs() << "    Group: " << flag.groupId << "\n";
        }
        outs() << "    Assignments: " << flag.assignments.size()
               << ", Checks: " << flag.checks.size() << "\n";
      }
    }

    outs() << "\nResults written to: " << OutputDir << "\n";
    return 0;
  }

  // Source mode (existing code)
  // Parse target files
  std::vector<std::string> targetFiles = splitString(TargetFiles, ',');

  if (targetFiles.empty()) {
    errs() << "Error: No target files specified\n";
    return 1;
  }

  outs() << "Target files:\n";
  for (const auto &f : targetFiles) {
    outs() << "  - " << f << "\n";
  }
  outs() << "\n";

  // Check if compile_commands path exists
  if (!sys::fs::exists(CompileCommandsPath)) {
    errs() << "Error: Compile commands path does not exist: "
           << CompileCommandsPath << "\n";
    return 1;
  }

  // Configure the analyzer
  FlagRecConfig config;

  config.compileCommandsPath = CompileCommandsPath;
  config.targetFiles = targetFiles;
  config.outputDir = OutputDir;
  config.verbose = Verbose;
  config.saveIntermediates = SaveIntermediates;

  // Constant finder config
  config.constantConfig.minGroupSize = MinGroupSize;
  config.constantConfig.ignorePrefixes = splitToSet(IgnorePrefixes, ',');

  // Variable filter config
  config.variableConfig.enableTaintAnalysis = EnableTaintAnalysis;
  config.variableConfig.conservativeMode = ConservativeMode;

  // Flag identifier config
  config.flagConfig.minConfidence = MinConfidence;

  // Run analysis
  FlagRecognizer recognizer(config);

  outs() << "Starting analysis...\n\n";

  AnalysisResult result;
  if (!recognizer.runAndWrite(result)) {
    errs() << "\nAnalysis failed!\n";
    return 1;
  }

  // Print summary
  outs() << "\n========================================\n";
  outs() << "Analysis Complete\n";
  outs() << "========================================\n\n";

  outs() << "Summary:\n";
  outs() << "  Constants found: " << result.stats.totalConstants << "\n";
  outs() << "  Constant groups: " << result.stats.totalGroups << "\n";
  outs() << "  Variables analyzed: " << result.stats.totalVariables << "\n";
  outs() << "  Input-related filtered: " << result.stats.filteredInputVars << "\n";
  outs() << "  Arithmetic filtered: " << result.stats.filteredArithmeticVars << "\n";
  outs() << "  Flag variables identified: "
         << result.flagVariables.size() << "\n\n";

  // Print top flag variables
  if (!result.flagVariables.empty()) {
    outs() << "Top Flag Variables:\n";
    for (const auto &flag : result.flagVariables) {
      outs() << "  - " << flag.name << " ("
             << (flag.confidence * 100) << "% confidence)\n";
      outs() << "    Location: " << flag.location.toString() << "\n";
      if (!flag.groupId.empty()) {
        outs() << "    Group: " << flag.groupId << "\n";
      }
      outs() << "    Assignments: " << flag.assignments.size()
             << ", Checks: " << flag.checks.size() << "\n";
    }
  }

  outs() << "\nResults written to: " << OutputDir << "\n";
  outs() << "  - flags.json\n";
  outs() << "  - report.md\n";

  if (SaveIntermediates) {
    outs() << "  - constants.json\n";
    outs() << "  - candidates.json\n";
  }

  outs() << "\n";

  return 0;
}
