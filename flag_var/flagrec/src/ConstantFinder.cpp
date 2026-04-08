//===-- ConstantFinder.cpp - Flag Constants Implementation ----*- C++ -*-===//
///
/// \file
/// Implementation of Module A: Flag Constants Identification
/// Simplified version using regex parsing instead of Clang AST
///
//===----------------------------------------------------------------------===//

#include "FlagRec.h"
#include "ConstantFinder.h"
#include "llvm/Support/raw_ostream.h"

#include <fstream>
#include <regex>
#include <sstream>
#include <algorithm>

using namespace llvm;

namespace flagrec {

//===----------------------------------------------------------------------===//
// SimpleConstantFinder - Regex-based constant extraction
//===----------------------------------------------------------------------===//

struct ParsedConstant {
  std::string name;
  int64_t value;
  ConstantType type;
  std::string groupName;
  unsigned line;
  std::string filename;  // Add filename
};

/// Extract enum constants from source file using regex
static std::vector<ParsedConstant> extractEnumConstants(const std::string &filename) {
  std::vector<ParsedConstant> result;

  std::ifstream file(filename);
  if (!file.is_open()) {
    return result;
  }

  std::string line;
  unsigned lineNum = 0;
  std::string currentEnum;
  bool inEnum = false;
  int lastEnumValue = -1;

  // Regex patterns
  std::regex enumStartRegex(R"(^\s*typedef\s+enum\s*(\w*)\s*\{?)");
  std::regex enumConstRegex(R"(^\s*(\w+)\s*(?:=\s*([^,]+))?)");
  std::regex enumEndRegex(R"(^\s*\}\s*(\w*)\s*;?)");
  std::regex hexRegex(R"(0[xX]([0-9A-Fa-f]+))");
  std::regex decRegex(R"(-?\d+)");

  while (std::getline(file, line)) {
    lineNum++;
    std::string trimmed = line;
    // Remove comments
    size_t commentPos = trimmed.find("//");
    if (commentPos != std::string::npos) {
      trimmed = trimmed.substr(0, commentPos);
    }

    // Check for enum start
    std::smatch match;
    if (std::regex_search(trimmed, match, enumStartRegex)) {
      inEnum = true;
      currentEnum = match[1].str();
      if (currentEnum.empty()) {
        currentEnum = "<anonymous>";
      }
      lastEnumValue = -1;
      continue;
    }

    // Check for enum end
    if (inEnum && std::regex_search(trimmed, match, enumEndRegex)) {
      inEnum = false;
      std::string enumName = match[1].str();
      if (!enumName.empty()) {
        currentEnum = enumName;
      }
      // Update group name for all constants in this enum
      for (auto &pc : result) {
        if (pc.groupName == "<pending>") {
          pc.groupName = currentEnum;
        }
      }
      continue;
    }

    // Check for enum constant
    if (inEnum && std::regex_search(trimmed, match, enumConstRegex)) {
      std::string constName = match[1].str();
      int64_t value = 0;

      if (match[2].matched) {
        // Explicit value
        std::string valueStr = match[2].str();
        std::smatch valueMatch;

        if (std::regex_search(valueStr, valueMatch, hexRegex)) {
          value = std::stoll(valueStr, nullptr, 16);
        } else if (std::regex_search(valueStr, valueMatch, decRegex)) {
          value = std::stoll(valueMatch[0].str());
        }
      } else {
        // Implicit value (previous + 1)
        value = lastEnumValue + 1;
      }

      lastEnumValue = value;

      ParsedConstant pc;
      pc.name = constName;
      pc.value = value;
      pc.type = ConstantType::Enum;
      pc.groupName = "<pending>";
      pc.line = lineNum;
      pc.filename = filename;
      result.push_back(pc);
    }
  }

  return result;
}

/// Extract macro constants from source file
static std::vector<ParsedConstant> extractMacroConstants(
    const std::string &filename,
    const std::set<std::string> &ignorePrefixes) {

  std::vector<ParsedConstant> result;

  std::ifstream file(filename);
  if (!file.is_open()) {
    return result;
  }

  std::string line;
  unsigned lineNum = 0;

  // Regex for #define NAME value
  std::regex macroRegex(
    R"(^\s*#\s*define\s+(\w+)\s+((?:0[xX][0-9A-Fa-f]+)|(?:\d+)))");

  while (std::getline(file, line)) {
    lineNum++;

    std::smatch match;
    if (std::regex_search(line, match, macroRegex)) {
      std::string name = match[1].str();

      // Check if should be ignored
      bool ignored = false;
      for (const auto &prefix : ignorePrefixes) {
        if (name.find(prefix) == 0) {
          ignored = true;
          break;
        }
      }
      if (ignored) continue;

      std::string valueStr = match[2].str();
      int64_t value = 0;

      if (valueStr.find("0x") == 0 || valueStr.find("0X") == 0) {
        value = std::stoll(valueStr, nullptr, 16);
      } else {
        value = std::stoll(valueStr);
      }

      // Extract prefix as group name
      std::string prefix;
      size_t us = name.find_last_of('_');
      if (us != std::string::npos && us > 0) {
        prefix = name.substr(0, us);
      } else {
        prefix = "<no_prefix>";
      }

      ParsedConstant pc;
      pc.name = name;
      pc.value = value;
      pc.type = ConstantType::Macro;
      pc.groupName = prefix;
      pc.line = lineNum;
      pc.filename = filename;
      result.push_back(pc);
    }
  }

  return result;
}

/// Extract const variables from source file
static std::vector<ParsedConstant> extractConstVariables(const std::string &filename) {
  std::vector<ParsedConstant> result;

  std::ifstream file(filename);
  if (!file.is_open()) {
    return result;
  }

  std::string line;
  unsigned lineNum = 0;

  // Simple regex for const int NAME = value;
  std::regex constRegex(
    R"(^\s*const\s+int\s+(\w+)\s*=\s*((?:0[xX][0-9A-Fa-f]+)|(?:\d+))\s*;)");

  while (std::getline(file, line)) {
    lineNum++;

    std::smatch match;
    if (std::regex_search(line, match, constRegex)) {
      std::string name = match[1].str();
      std::string valueStr = match[2].str();
      int64_t value = 0;

      if (valueStr.find("0x") == 0 || valueStr.find("0X") == 0) {
        value = std::stoll(valueStr, nullptr, 16);
      } else {
        value = std::stoll(valueStr);
      }

      ParsedConstant pc;
      pc.name = name;
      pc.value = value;
      pc.type = ConstantType::ConstVar;
      pc.groupName = "<const_var>";
      pc.line = lineNum;
      pc.filename = filename;
      result.push_back(pc);
    }
  }

  return result;
}

//===----------------------------------------------------------------------===//
// ConstantFinder Implementation
//===----------------------------------------------------------------------===//

ConstantFinder::ConstantFinder(const ConstantFinderConfig &cfg)
    : config(cfg) {
  // Simplified constructor
}

AnalysisResult::Stats
ConstantFinder::findConstants(const std::string &compileCommandsPath,
                              const std::vector<std::string> &targetFiles,
                              std::vector<ConstantGroup> &outGroups) {
  AnalysisResult::Stats stats;
  std::vector<ParsedConstant> allParsed;

  for (const auto &sourceFile : targetFiles) {
    // Extract all types of constants
    auto enums = extractEnumConstants(sourceFile);
    auto macros = extractMacroConstants(sourceFile, config.ignorePrefixes);
    auto consts = extractConstVariables(sourceFile);

    allParsed.insert(allParsed.end(), enums.begin(), enums.end());
    allParsed.insert(allParsed.end(), macros.begin(), macros.end());
    allParsed.insert(allParsed.end(), consts.begin(), consts.end());
  }

  stats.totalConstants = allParsed.size();

  // Group constants
  clusterParsedConstants(allParsed, outGroups);
  stats.totalGroups = outGroups.size();

  return stats;
}

bool ConstantFinder::findConstantsInFile(
    const std::string &sourceFile,
    const std::vector<std::string> &compileArgs,
    std::vector<ConstantGroup> &outGroups) {

  std::vector<ParsedConstant> allParsed;

  auto enums = extractEnumConstants(sourceFile);
  auto macros = extractMacroConstants(sourceFile, config.ignorePrefixes);
  auto consts = extractConstVariables(sourceFile);

  allParsed.insert(allParsed.end(), enums.begin(), enums.end());
  allParsed.insert(allParsed.end(), macros.begin(), macros.end());
  allParsed.insert(allParsed.end(), consts.begin(), consts.end());

  clusterParsedConstants(allParsed, outGroups);
  return !outGroups.empty();
}

bool ConstantFinder::extractMacroConstantsWithCompileInfo(
    const std::string &sourceFile,
    const std::vector<std::string> &compileArgs,
    std::vector<RawConstant> &outMacros) {
  // This function is kept for API compatibility but not used in simplified version
  return false;
}

void ConstantFinder::clusterParsedConstants(
    const std::vector<ParsedConstant> &parsed,
    std::vector<ConstantGroup> &outGroups) {

  // Group by groupName
  std::map<std::string, std::vector<ParsedConstant>> groupMap;

  for (const auto &pc : parsed) {
    groupMap[pc.groupName].push_back(pc);
  }

  int groupId = 0;
  for (auto &entry : groupMap) {
    const std::string &groupName = entry.first;
    std::vector<ParsedConstant> &consts = entry.second;

    if (consts.size() < static_cast<size_t>(config.minGroupSize)) {
      continue;
    }

    // Check common prefix
    std::string commonPrefix = extractCommonPrefix(consts);

    // Skip if prefix is in ignore list
    bool shouldSkip = false;
    for (const auto &ignore : config.ignorePrefixes) {
      if (commonPrefix == ignore) {
        shouldSkip = true;
        break;
      }
    }
    if (shouldSkip) continue;

    // Check if most constants share a prefix
    if (config.requireCommonPrefix && commonPrefix.length() < 2) {
      // Skip groups without meaningful prefix
      continue;
    }

    ConstantGroup group;
    group.id = "group_" + std::to_string(groupId++);
    group.commonPrefix = commonPrefix;
    group.type = consts[0].type;
    group.location.file = "<multiple>";
    group.location.line = consts[0].line;

    for (const auto &pc : consts) {
      FlagConstant fc;
      fc.name = pc.name;
      fc.value = pc.value;
      fc.type = pc.type;
      // Use the actual filename from the parsed constant
      fc.location.file = pc.filename.empty() ? "<source>" : pc.filename;
      fc.location.line = pc.line;
      fc.groupName = group.id;
      group.constants.push_back(fc);
    }

    outGroups.push_back(group);
  }
}

std::string ConstantFinder::extractCommonPrefix(
    const std::vector<ParsedConstant> &consts) const {

  if (consts.empty()) {
    return "";
  }

  // Extract the common prefix from the actual constant names
  // This gives us the actual prefix used in the code (e.g., "MODE" from MODE_READ)
  std::string prefix = consts[0].name;

  for (size_t i = 1; i < consts.size(); ++i) {
    size_t j = 0;
    while (j < prefix.length() && j < consts[i].name.length() &&
           prefix[j] == consts[i].name[j]) {
      j++;
    }
    prefix = prefix.substr(0, j);
    if (prefix.empty()) {
      break;
    }
  }

  // Find last underscore and keep it (e.g., "MODE_" from "MODE_READ")
  size_t lastUnderscore = prefix.find_last_of('_');
  if (lastUnderscore != std::string::npos) {
    prefix = prefix.substr(0, lastUnderscore + 1);
  }

  // If prefix is too short, try using groupName as fallback for enums
  if (prefix.length() < 2) {
    if (!consts[0].groupName.empty() &&
        consts[0].groupName != "<anonymous>" &&
        consts[0].groupName != "<const_var>" &&
        consts[0].groupName != "<no_prefix>") {
      // For enums, try to extract a shortened prefix from the type name
      // e.g., "FileMode" -> "mode" for matching with current_mode
      std::string typeName = consts[0].groupName;
      // Convert to lowercase and remove common suffixes
      std::transform(typeName.begin(), typeName.end(), typeName.begin(), ::tolower);
      // Remove common prefixes
      size_t pos;
      if ((pos = typeName.find("file")) == 0) typeName = typeName.substr(4);
      else if ((pos = typeName.find("device")) == 0) typeName = typeName.substr(6);
      return typeName + "_";  // Return with underscore
    }
  }

  return prefix;
}

// Stub implementations for API compatibility
bool ConstantFinder::shouldGroup(const RawConstant &c1,
                                 const RawConstant &c2) const {
  return false;
}

std::vector<std::vector<RawConstant>>
ConstantFinder::groupBySemantics(const std::vector<RawConstant> &constants) const {
  return std::vector<std::vector<RawConstant>>();
}

void ConstantFinder::assignMacroGroups(
    std::vector<RawConstant> &macros,
    std::vector<ConstantGroup> &groups) const {
}

void ConstantFinder::clusterConstants(
    const std::vector<RawConstant> &rawConsts,
    std::vector<ConstantGroup> &outGroups) {
}

} // namespace flagrec
