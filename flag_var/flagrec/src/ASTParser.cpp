//===-- ASTParser.cpp - AST-based Analysis Implementation ----*- C++ -*-===//
///
/// \file
/// Implementation of AST parser for extracting struct definitions,
/// flag-like fields, and member access patterns from C/C++ source files.
///
/// This implementation provides two approaches:
/// 1. Simple regex-based parsing (always available)
/// 2. Clang AST-based parsing (when Clang libtooling is available)
///
//===----------------------------------------------------------------------===//

#include "ASTParser.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>

using namespace llvm;

namespace flagrec {

//===----------------------------------------------------------------------===//
// SimpleASTParser Implementation (Regex-based)
//===----------------------------------------------------------------------===//

bool SimpleASTParser::parseStructs(const std::string &sourceFile,
                                   std::vector<StructInfo> &outStructs) {
  std::ifstream file(sourceFile);
  if (!file.is_open()) {
    return false;
  }

  outStructs.clear();
  std::string line;
  int lineNumber = 0;
  StructInfo *currentStruct = nullptr;
  bool inStruct = false;
  bool inTypedef = false;
  int braceLevel = 0;

  std::string currentFile = sys::path::filename(sourceFile).str();

  while (std::getline(file, line)) {
    lineNumber++;
    std::string trimmed = line;
    size_t start = trimmed.find_first_not_of(" \t\n\r");
    if (start != std::string::npos) {
      trimmed = trimmed.substr(start);
    }
    size_t end = trimmed.find_last_not_of(" \t\n\r");
    if (end != std::string::npos) {
      trimmed = trimmed.substr(0, end + 1);
    }

    // Check for struct definition start
    // Patterns: "struct name {" or "struct name\n{"
    std::regex structRegex(R"(struct\s+(\w+)\s*\{?)");
    std::smatch match;
    if (std::regex_search(trimmed, match, structRegex)) {
      std::string structName = match[1].str();

      // Skip common non-interesting structs
      if (structName.empty() ||
          structName.find("anon") != std::string::npos) {
        continue;
      }

      StructInfo info;
      info.name = structName;
      info.location = SourceLocation(currentFile, lineNumber);
      outStructs.push_back(info);
      currentStruct = &outStructs.back();
      inStruct = true;

      // Check if brace is on same line
      if (trimmed.find('{') != std::string::npos) {
        braceLevel = 1;
      } else {
        braceLevel = 0;
      }
      continue;
    }

    // Track brace level
    if (inStruct) {
      braceLevel += std::count(trimmed.begin(), trimmed.end(), '{');
      braceLevel -= std::count(trimmed.begin(), trimmed.end(), '}');

      if (braceLevel <= 0 && currentStruct != nullptr) {
        inStruct = false;
        currentStruct = nullptr;
        continue;
      }

      // Parse fields inside struct
      if (currentStruct != nullptr && braceLevel == 1) {
        // Skip comments and empty lines
        if (trimmed.empty() || trimmed[0] == '#' ||
            trimmed.substr(0, 2) == "//" || trimmed.substr(0, 2) == "/*") {
          continue;
        }

        // Skip closing brace line
        if (trimmed.find('}') != std::string::npos) {
          continue;
        }

        // Parse field declaration
        // Pattern: "type field_name;" or "type field_name [array_size];"
        // Also handle bitfields: "type field_name : bits;"
        StructField field;
        if (parseField(trimmed, field)) {
          currentStruct->fields.push_back(field);
          if (field.isFlagLike) {
            currentStruct->flagLikeFields.insert(field.name);
          }
        }
      }
    }
  }

  file.close();
  return !outStructs.empty();
}

bool SimpleASTParser::parseField(const std::string &line, StructField &outField) {
  outField = StructField();

  // Skip lines with braces
  if (line.find('{') != std::string::npos || line.find('}') != std::string::npos) {
    return false;
  }

  // Remove trailing semicolon and comments
  std::string cleaned = line;
  size_t semiPos = cleaned.find(';');
  if (semiPos != std::string::npos) {
    cleaned = cleaned.substr(0, semiPos);
  }

  size_t commentPos = cleaned.find("//");
  if (commentPos != std::string::npos) {
    cleaned = cleaned.substr(0, commentPos);
  }

  // Trim whitespace
  size_t start = cleaned.find_first_not_of(" \t");
  if (start == std::string::npos) return false;
  cleaned = cleaned.substr(start);

  size_t end = cleaned.find_last_not_of(" \t");
  if (end == std::string::npos) return false;
  cleaned = cleaned.substr(0, end + 1);

  // Skip empty or special keywords
  if (cleaned.empty() || cleaned == "struct" || cleaned == "union" ||
      cleaned == "enum" || cleaned == "typedef") {
    return false;
  }

  // Parse: "type field_name" or "type field_name : bits"
  // Handle const, volatile, unsigned, signed qualifiers
  std::vector<std::string> tokens;
  std::string token;
  std::istringstream iss(cleaned);
  while (iss >> token) {
    tokens.push_back(token);
  }

  if (tokens.size() < 2) {
    return false;
  }

  // Last token is field name (possibly with bitfield or array)
  std::string lastToken = tokens.back();
  std::string fieldName = lastToken;

  // Remove bitfield specification
  size_t colonPos = fieldName.find(':');
  if (colonPos != std::string::npos) {
    fieldName = fieldName.substr(0, colonPos);
  }

  // Remove array specification
  size_t bracketPos = fieldName.find('[');
  if (bracketPos != std::string::npos) {
    fieldName = fieldName.substr(0, bracketPos);
  }

  // Remove pointer/reference symbols
  fieldName.erase(std::remove(fieldName.begin(), fieldName.end(), '*'), fieldName.end());
  fieldName.erase(std::remove(fieldName.begin(), fieldName.end(), '&'), fieldName.end());

  if (fieldName.empty()) {
    return false;
  }

  // Build type name from all tokens except the last
  std::string typeName;
  for (size_t i = 0; i < tokens.size() - 1; ++i) {
    if (!typeName.empty()) typeName += " ";
    typeName += tokens[i];
  }

  outField.name = fieldName;
  outField.typeName = typeName;

  // Check if flag-like
  outField.isFlagLike = isFlagLikeFieldName(fieldName, {
    "mode", "modes", "flag", "flags", "state", "states",
    "status", "transform", "transforms", "transformation", "transformations",
    "option", "options", "setting", "settings", "config", "configs",
    "control", "type", "stage", "phase", "condition", "property",
    "attr", "attrs", "attribute", "attributes", "caps", "capability",
    "capabilities", "perm", "perms", "permission", "permissions",
    "mask", "masks", "bit", "bits", "reg", "regs", "register", "registers"
  });

  return true;
}

bool SimpleASTParser::isFlagLikeFieldName(const std::string &fieldName,
                                          const std::set<std::string> &patterns) {
  std::string lowerName = fieldName;
  std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

  // Direct match
  if (patterns.find(lowerName) != patterns.end()) {
    return true;
  }

  // Contains flag-like pattern
  for (const auto &pattern : patterns) {
    if (lowerName.find(pattern) != std::string::npos) {
      return true;
    }
  }

  return false;
}

std::string SimpleASTParser::extractStructName(const std::string &line) {
  std::regex structRegex(R"(struct\s+(\w+))");
  std::smatch match;
  if (std::regex_search(line, match, structRegex)) {
    return match[1].str();
  }
  return "";
}

bool SimpleASTParser::isMemberAccess(const std::string &line,
                                     MemberAccess &outAccess) {
  // Match patterns like:
  // - ptr->field
  // - obj.field
  // - ptr->field |= value
  // - if (ptr->field & value)

  std::regex arrowRegex(R"((\w+)\s*->\s*(\w+))");
  std::regex dotRegex(R"((\w+)\.(\w+))");

  std::smatch match;
  std::string arrowBase, arrowField, dotBase, dotField;

  // Check for -> first (more common for struct pointers)
  if (std::regex_search(line, match, arrowRegex)) {
    if (match.size() >= 3) {
      outAccess.baseName = match[1].str();
      outAccess.fieldName = match[2].str();
      outAccess.operatorType = "->";
      return true;
    }
  }

  // Check for .
  if (std::regex_search(line, match, dotRegex)) {
    if (match.size() >= 3) {
      outAccess.baseName = match[1].str();
      outAccess.fieldName = match[2].str();
      outAccess.operatorType = ".";
      return true;
    }
  }

  return false;
}

std::string SimpleASTParser::findContainingFunction(const std::string &sourceFile,
                                                     int lineNumber) {
  std::ifstream file(sourceFile);
  if (!file.is_open()) {
    return "";
  }

  std::string line;
  int currentLine = 0;
  std::string currentFunction;

  // Simple approach: find the last function declaration before lineNumber
  std::regex funcRegex(R"((\w+)\s*\([^)]*\)\s*\{?)");

  while (std::getline(file, line) && currentLine < lineNumber) {
    currentLine++;
    std::smatch match;
    if (std::regex_search(line, match, funcRegex)) {
      // Make sure it's not a control structure
      std::string stripped = line;
      size_t start = stripped.find_first_not_of(" \t");
      if (start != std::string::npos) {
        stripped = stripped.substr(start);
      }
      if (stripped.substr(0, 2) != "if" &&
          stripped.substr(0, 3) != "for" &&
          stripped.substr(0, 5) != "while" &&
          stripped.substr(0, 6) != "switch") {
        currentFunction = match[1].str();
      }
    }
  }

  file.close();
  return currentFunction;
}

bool SimpleASTParser::parseMemberAccesses(const std::string &sourceFile,
                                          std::vector<MemberAccess> &outAccesses) {
  std::ifstream file(sourceFile);
  if (!file.is_open()) {
    return false;
  }

  outAccesses.clear();
  std::string line;
  int lineNumber = 0;
  std::string currentFunction;

  std::string currentFile = sys::path::filename(sourceFile).str();

  while (std::getline(file, line)) {
    lineNumber++;

    // Track function context
    std::regex funcRegex(R"((\w+)\s*\([^)]*\)\s*\{)");
    std::smatch funcMatch;
    if (std::regex_search(line, funcMatch, funcRegex)) {
      currentFunction = funcMatch[1].str();
    }

    MemberAccess access;
    if (isMemberAccess(line, access)) {
      access.location = SourceLocation(currentFile, lineNumber);
      access.containingFunction = currentFunction;
      outAccesses.push_back(access);
    }
  }

  file.close();
  return !outAccesses.empty();
}

//===----------------------------------------------------------------------===//
// ASTParser Implementation
//===----------------------------------------------------------------------===//

class ASTParser::Impl {
public:
  Impl(ASTParserConfig &cfg) : config(cfg) {}

  ASTParserConfig &config;
};

ASTParser::ASTParser(const ASTParserConfig &config)
    : config(config), pImpl(std::make_unique<Impl>(const_cast<ASTParserConfig&>(config))) {}

ASTParser::~ASTParser() = default;

bool ASTParser::parseSourceFile(const std::string &sourceFile,
                                const std::vector<std::string> &compileArgs) {
  // Use SimpleASTParser (regex-based) for now
  // TODO: Add Clang AST-based parsing when libtooling is available

  if (config.verbose) {
    llvm::outs() << "Parsing source file: " << sourceFile << "\n";
  }

  // Parse structs
  std::vector<StructInfo> fileStructs;
  if (SimpleASTParser::parseStructs(sourceFile, fileStructs)) {
    structs.insert(structs.end(), fileStructs.begin(), fileStructs.end());
    stats.structsFound += fileStructs.size();

    for (const auto &s : fileStructs) {
      stats.flagLikeFieldsFound += s.flagLikeFields.size();
      if (config.verbose) {
        llvm::outs() << "  Found struct: " << s.name
                     << " with " << s.fields.size() << " fields ("
                     << s.flagLikeFields.size() << " flag-like)\n";
        for (const auto &f : s.getFlagLikeFields()) {
          llvm::outs() << "    - " << f.name << " (" << f.typeName << ")\n";
        }
      }
    }
  }

  // Parse member accesses
  std::vector<MemberAccess> fileAccesses;
  if (SimpleASTParser::parseMemberAccesses(sourceFile, fileAccesses)) {
    memberAccesses.insert(memberAccesses.end(), fileAccesses.begin(), fileAccesses.end());
    stats.memberAccessesFound += fileAccesses.size();
  }

  return true;
}

bool ASTParser::parseSourceFiles(const std::vector<std::string> &sourceFiles,
                                 const std::vector<std::string> &compileArgs) {
  bool success = true;

  for (const auto &file : sourceFiles) {
    if (!parseSourceFile(file, compileArgs)) {
      success = false;
    }
  }

  return success;
}

const StructInfo* ASTParser::findStruct(const std::string &name) const {
  for (const auto &s : structs) {
    if (s.name == name) {
      return &s;
    }
  }
  return nullptr;
}

std::vector<StructField> ASTParser::getAllFlagLikeFields() const {
  std::vector<StructField> result;
  for (const auto &s : structs) {
    auto flagFields = s.getFlagLikeFields();
    result.insert(result.end(), flagFields.begin(), flagFields.end());
  }
  return result;
}

std::vector<MemberAccess> ASTParser::getMemberAccessesForField(
    const std::string &fieldName) const {
  std::vector<MemberAccess> result;
  for (const auto &access : memberAccesses) {
    if (access.fieldName == fieldName) {
      result.push_back(access);
    }
  }
  return result;
}

std::vector<MemberAccess> ASTParser::getMemberAccessesForBase(
    const std::string &baseName) const {
  std::vector<MemberAccess> result;
  for (const auto &access : memberAccesses) {
    if (access.baseName == baseName) {
      result.push_back(access);
    }
  }
  return result;
}

bool ASTParser::isFlagLikeFieldName(const std::string &fieldName) const {
  return SimpleASTParser::isFlagLikeFieldName(fieldName, config.flagLikePatterns);
}

void ASTParser::clear() {
  structs.clear();
  variables.clear();
  memberAccesses.clear();
  stats = Stats();
}

} // namespace flagrec
