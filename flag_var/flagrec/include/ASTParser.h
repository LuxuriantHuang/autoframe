//===-- ASTParser.h - AST-based Variable and Struct Analysis ---*- C++ -*-===//
///
/// \file
/// Module for parsing C/C++ source files using Clang's AST to extract:
/// - Struct definitions and their fields
/// - Field names that are flag-like (mode, flags, state, transformations, etc.)
/// - Variable declarations with accurate locations
/// - Member access patterns
///
//===----------------------------------------------------------------------===//

#ifndef FLAGREC_ASTPARSER_H
#define FLAGREC_ASTPARSER_H

#include "Types.h"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>

namespace flagrec {

/// Information about a struct field
struct StructField {
  std::string name;              // Field name
  std::string typeName;          // Type of the field (int, unsigned, etc.)
  SourceLocation location;       // Location in source file
  bool isFlagLike;               // Is this a flag-like field based on name

  StructField() : isFlagLike(false) {}
  StructField(const std::string &n, const std::string &t,
              const SourceLocation &loc, bool flagLike = false)
      : name(n), typeName(t), location(loc), isFlagLike(flagLike) {}
};

/// Information about a struct definition
struct StructInfo {
  std::string name;              // Struct name
  SourceLocation location;       // Definition location
  std::vector<StructField> fields;  // All fields
  std::set<std::string> flagLikeFields;  // Names of flag-like fields

  /// Get all flag-like fields
  std::vector<StructField> getFlagLikeFields() const {
    std::vector<StructField> result;
    for (const auto &field : fields) {
      if (field.isFlagLike) {
        result.push_back(field);
      }
    }
    return result;
  }
};

/// Information about a variable declaration
struct VariableDecl {
  std::string name;              // Variable name
  std::string typeName;          // Type name
  SourceLocation location;       // Declaration location
  std::string scope;             // Function name or "global"

  bool isPointer;                // Is it a pointer type
  bool isStructPointer;          // Points to a struct

  VariableDecl() : isPointer(false), isStructPointer(false) {}
};

/// Information about a member access expression (e.g., ptr->field)
struct MemberAccess {
  std::string baseName;          // Base variable name (e.g., "png_ptr")
  std::string fieldName;         // Field name (e.g., "mode")
  std::string operatorType;      // "->" or "."
  SourceLocation location;       // Access location
  std::string containingFunction;// Function containing the access

  /// Get full display name
  std::string getDisplayName() const {
    return baseName + operatorType + fieldName;
  }
};

/// Configuration for AST parser
struct ASTParserConfig {
  // Flag-like field name patterns
  std::set<std::string> flagLikePatterns;

  // Additional patterns to consider as flag-like
  std::set<std::string> customPatterns;

  bool verbose;                  // Print debug information

  ASTParserConfig() : verbose(false) {
    // Common flag-like patterns
    flagLikePatterns = {
      "mode", "modes",
      "flag", "flags",
      "state", "states",
      "status", "statuses",
      "transform", "transforms", "transformation", "transformations",
      "option", "options",
      "setting", "settings",
      "config", "configs",
      "control", "controls",
      "type", "types",           // when in struct context
      "stage", "stages",
      "phase", "phases",
      "condition", "conditions",
      "property", "properties",
      "attr", "attrs", "attribute", "attributes",
      "caps", "capability", "capabilities",
      "perm", "perms", "permission", "permissions",
      "mask", "masks",
      "bit", "bits",
      "reg", "regs", "register", "registers"
    };
  }
};

/// Main AST parser class
class ASTParser {
public:
  ASTParser(const ASTParserConfig &config = ASTParserConfig());
  ~ASTParser();

  /// Parse a single source file
  bool parseSourceFile(const std::string &sourceFile,
                       const std::vector<std::string> &compileArgs = {});

  /// Parse multiple source files
  bool parseSourceFiles(const std::vector<std::string> &sourceFiles,
                        const std::vector<std::string> &compileArgs = {});

  /// Get all parsed struct information
  const std::vector<StructInfo>& getStructs() const { return structs; }

  /// Get all parsed variable declarations
  const std::vector<VariableDecl>& getVariables() const { return variables; }

  /// Get all member access expressions
  const std::vector<MemberAccess>& getMemberAccesses() const { return memberAccesses; }

  /// Find struct by name
  const StructInfo* findStruct(const std::string &name) const;

  /// Find all flag-like fields across all structs
  std::vector<StructField> getAllFlagLikeFields() const;

  /// Get member accesses for a specific field
  std::vector<MemberAccess> getMemberAccessesForField(
      const std::string &fieldName) const;

  /// Get member accesses for a specific base variable
  std::vector<MemberAccess> getMemberAccessesForBase(
      const std::string &baseName) const;

  /// Check if a field name is flag-like
  bool isFlagLikeFieldName(const std::string &fieldName) const;

  /// Get statistics
  struct Stats {
    int structsFound;
    int flagLikeFieldsFound;
    int variablesFound;
    int memberAccessesFound;

    Stats() : structsFound(0), flagLikeFieldsFound(0),
               variablesFound(0), memberAccessesFound(0) {}
  };

  Stats getStats() const { return stats; }

  /// Clear all parsed data
  void clear();

private:
  ASTParserConfig config;
  Stats stats;

  std::vector<StructInfo> structs;
  std::vector<VariableDecl> variables;
  std::vector<MemberAccess> memberAccesses;

  // Internal implementation
  class Impl;
  std::unique_ptr<Impl> pImpl;
};

/// Utility: Simple regex-based AST parser fallback
/// This is used when Clang libtooling is not available
class SimpleASTParser {
public:
  /// Parse struct definitions from source file using regex
  static bool parseStructs(const std::string &sourceFile,
                          std::vector<StructInfo> &outStructs);

  /// Parse member accesses from source file using regex
  static bool parseMemberAccesses(const std::string &sourceFile,
                                 std::vector<MemberAccess> &outAccesses);

  /// Check if field name is flag-like
  static bool isFlagLikeFieldName(const std::string &fieldName,
                                 const std::set<std::string> &patterns);

private:
  /// Extract struct name from definition line
  static std::string extractStructName(const std::string &line);

  /// Parse field declaration
  static bool parseField(const std::string &line, StructField &outField);

  /// Check if line contains struct member access
  static bool isMemberAccess(const std::string &line,
                            MemberAccess &outAccess);

  /// Find function name containing a line
  static std::string findContainingFunction(const std::string &sourceFile,
                                           int lineNumber);
};

} // namespace flagrec

#endif // FLAGREC_ASTPARSER_H
