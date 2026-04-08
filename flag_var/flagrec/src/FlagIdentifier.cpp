//===-- FlagIdentifier.cpp - Flag Variable Identification ----*- C++ -*-===//
///
/// \file
/// Implementation of Module C: Flag Variable Identification
/// Matches variables with constant groups and collects usage points.
///
//===----------------------------------------------------------------------===//

#include "FlagRec.h"
#include "FlagIdentifier.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <set>

using namespace llvm;

namespace flagrec {

//===----------------------------------------------------------------------===//
// FlagIdentifier Implementation
//===----------------------------------------------------------------------===//

FlagIdentifier::FlagIdentifier(const FlagIdentifierConfig &cfg)
    : config(cfg) {
  stats = {};
}

bool FlagIdentifier::identifyFlags(
    const std::vector<VarCandidate> &candidates,
    const std::vector<ConstantGroup> &groups,
    std::vector<FlagVariable> &outFlags) {

  stats.totalCandidates = candidates.size();
  outFlags.clear();

  for (const auto &candidate : candidates) {
    // Skip loop variables - they are not flag variables
    if (candidate.isLoopVariable) {
      stats.lowConfidenceFiltered++;
      continue;
    }

    VarAnalysisContext ctx;
    ctx.candidate = candidate;

    // Match to group
    ctx.matchedGroupId = matchToGroup(candidate, groups);

    // Get group values if matched
    std::set<int64_t> groupValues;
    if (!ctx.matchedGroupId.empty()) {
      for (const auto &g : groups) {
        if (g.id == ctx.matchedGroupId) {
          groupValues = g.getValues();
          break;
        }
      }
    }

    // Check if candidate has assigned constants matching the group
    bool hasGroupMatch = false;
    if (!groupValues.empty() && !candidate.assignedConstants.empty()) {
      for (int64_t val : candidate.assignedConstants) {
        if (groupValues.count(val)) {
          hasGroupMatch = true;
          break;
        }
      }
    }

    // Calculate confidence
    const ConstantGroup *matchedGroup = nullptr;
    if (!ctx.matchedGroupId.empty()) {
      for (const auto &g : groups) {
        if (g.id == ctx.matchedGroupId) {
          matchedGroup = &g;
          break;
        }
      }
    }

    ctx.confidence = calculateConfidence(ctx, matchedGroup);

    // Add assignment/check info from candidate
    // Note: We use the candidate's assignedConstants as hints
    for (int64_t val : candidate.assignedConstants) {
      if (groupValues.empty() || groupValues.count(val)) {
        AssignmentPoint ap;
        ap.location = candidate.location;
        ap.assignedValue = val;
        ap.assignment = candidate.name + " = " + std::to_string(val);
        ctx.assignments.push_back(ap);
      }
    }

    if (candidate.hasComparisons) {
      CheckPoint cp;
      cp.location = candidate.location;
      cp.checkType = CheckType::Equal;
      cp.comparedValue = 0;  // Unknown
      cp.condition = candidate.name + " compared";
      ctx.checks.push_back(cp);
    }

    // Filter by minimum confidence
    if (ctx.confidence >= config.minConfidence) {
      FlagVariable flagVar;
      // Use display name for struct members
      flagVar.name = candidate.getDisplayName();
      flagVar.typeName = candidate.typeName;
      flagVar.function = candidate.function;
      flagVar.location = candidate.location;
      flagVar.groupId = ctx.matchedGroupId;
      flagVar.assignments = ctx.assignments;
      flagVar.checks = ctx.checks;
      flagVar.confidence = ctx.confidence;
      outFlags.push_back(flagVar);
      stats.finalFlagVars++;
    } else {
      stats.lowConfidenceFiltered++;
    }

    // Check if matched to a group
    if (!ctx.matchedGroupId.empty()) {
      stats.matchedToGroups++;
    }
  }

  return true;
}

bool FlagIdentifier::identifyFlagsFromIR(
    Module *module,
    const std::vector<ConstantGroup> &groups,
    const std::vector<VarCandidate> &candidates,
    std::vector<FlagVariable> &outFlags) {

  if (!module) {
    return false;
  }

  stats.totalCandidates = candidates.size();
  outFlags.clear();

  for (const auto &candidate : candidates) {
    if (!candidate.value) continue;

    VarAnalysisContext ctx;
    ctx.candidate = candidate;
    analyzeVariable(candidate.value, candidate, groups, ctx);

    // Similar processing as above
    if (!ctx.matchedGroupId.empty()) {
      stats.matchedToGroups++;
    }

    const ConstantGroup *matchedGroup = nullptr;
    if (!ctx.matchedGroupId.empty()) {
      for (const auto &g : groups) {
        if (g.id == ctx.matchedGroupId) {
          matchedGroup = &g;
          break;
        }
      }
    }

    ctx.confidence = calculateConfidence(ctx, matchedGroup);

    if (ctx.confidence >= config.minConfidence) {
      FlagVariable flagVar;
      flagVar.name = candidate.name;
      flagVar.typeName = candidate.typeName;
      flagVar.function = candidate.function;
      flagVar.location = candidate.location;
      flagVar.groupId = ctx.matchedGroupId;
      flagVar.assignments = ctx.assignments;
      flagVar.checks = ctx.checks;
      flagVar.confidence = ctx.confidence;
      outFlags.push_back(flagVar);
      stats.finalFlagVars++;
    } else {
      stats.lowConfidenceFiltered++;
    }
  }

  return true;
}

double FlagIdentifier::calculateConfidence(
    const VarAnalysisContext &ctx,
    const ConstantGroup *group) const {

  double score = 0.0;

  // Basic flag-like properties
  if (ctx.candidate.hasStoresFromConst) {
    score += 0.3;
  }
  if (ctx.candidate.hasComparisons) {
    score += 0.2;
  }
  if (ctx.candidate.hasBitOps) {
    score += 0.15;
  }

  // Bonus for struct members (they are more likely to be flag variables)
  if (ctx.candidate.isStructMember) {
    score += 0.1;

    // Extra bonus for flag-like field names
    std::string lowerName = ctx.candidate.fieldName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    if (lowerName.find("mode") != std::string::npos ||
        lowerName.find("flag") != std::string::npos ||
        lowerName.find("state") != std::string::npos ||
        lowerName.find("transform") != std::string::npos) {
      score += 0.15;
    }

    // Extra bonus for |= pattern (strong flag indicator)
    if (ctx.candidate.hasBitwiseOrStore) {
      score += 0.2;
    }
  }

  // Group match score
  if (group) {
    const auto &assignedConsts = ctx.candidate.assignedConstants;
    double groupScore = calculateGroupMatch(assignedConsts, *group);
    score += groupScore * 0.3;
  }

  // Check points (flag usage)
  if (!ctx.checks.empty()) {
    score += 0.1;
  }

  return std::min(score, 1.0);
}

std::string FlagIdentifier::matchToGroup(
    const VarCandidate &candidate,
    const std::vector<ConstantGroup> &groups) const {

  std::string bestGroup;
  double bestScore = 0.0;

  // Get the appropriate name for matching
  std::string varName = candidate.name;
  if (candidate.isStructMember && !candidate.fieldName.empty()) {
    varName = candidate.fieldName;
  }

  // Convert to lowercase for comparison
  std::string varNameLower = varName;
  std::transform(varNameLower.begin(), varNameLower.end(), varNameLower.begin(), ::tolower);

  // Score based on name prefix matching with constant group prefix
  for (const auto &group : groups) {
    double score = 0.0;

    // Check if variable name contains group prefix (case-insensitive)
    std::string groupName = group.commonPrefix;
    std::string groupNameLower;  // Declare outside the if block
    if (!groupName.empty()) {
      groupNameLower = groupName;
      std::transform(groupNameLower.begin(), groupNameLower.end(), groupNameLower.begin(), ::tolower);

      if (varNameLower.find(groupNameLower) != std::string::npos) {
        score += 0.5;  // Medium score for prefix match
      }

      // Also check for partial matches (e.g., "mode" matches "MODE_")
      std::string prefixNoUnderscore = groupNameLower;
      if (!prefixNoUnderscore.empty() && prefixNoUnderscore.back() == '_') {
        prefixNoUnderscore = prefixNoUnderscore.substr(0, prefixNoUnderscore.length() - 1);
      }
      if (!prefixNoUnderscore.empty() && varNameLower.find(prefixNoUnderscore) != std::string::npos) {
        score += 0.4;
      }
    }

    // NEW: Struct member specific matching
    if (candidate.isStructMember) {
      // Match field names to constant group patterns
      std::string fieldName = candidate.fieldName;
      std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), ::tolower);

      // Field name to constant prefix mappings
      bool fieldMatchesGroup = false;
      if (fieldName.find("transform") != std::string::npos) {
        // transformations field matches PNG_TRANSFORM_* or similar
        if (!groupNameLower.empty() && (
            groupNameLower.find("transform") != std::string::npos ||
            groupNameLower.find("png_") == 0)) {
          score += 0.6;
          fieldMatchesGroup = true;
        }
      }
      else if (fieldName.find("mode") != std::string::npos) {
        // mode field matches *_MODE or HAVE_* constants
        if (!groupNameLower.empty() && (
            groupNameLower.find("mode") != std::string::npos ||
            groupNameLower.find("have_") != std::string::npos ||
            groupNameLower.find("png_") == 0)) {
          score += 0.6;
          fieldMatchesGroup = true;
        }
      }
      else if (fieldName.find("flag") != std::string::npos) {
        // flags field matches *_FLAG_* constants
        if (!groupNameLower.empty() && groupNameLower.find("flag") != std::string::npos) {
          score += 0.6;
          fieldMatchesGroup = true;
        }
      }
      else if (fieldName.find("state") != std::string::npos) {
        // state field matches STATE_* constants
        if (!groupNameLower.empty() && groupNameLower.find("state") != std::string::npos) {
          score += 0.6;
          fieldMatchesGroup = true;
        }
      }

      // Extra bonus for struct members with |= pattern (strong flag indicator)
      if (candidate.hasBitwiseOrStore) {
        score += 0.3;
      }
    }

    // Check for common flag-related variable name patterns
    if (varNameLower.find("mode") != std::string::npos ||
        varNameLower.find("state") != std::string::npos ||
        varNameLower.find("flag") != std::string::npos ||
        varNameLower.find("status") != std::string::npos ||
        varNameLower.find("option") != std::string::npos) {
      score += 0.2;
    }

    // For global variables, give extra points if they're int type
    if (candidate.isGlobal && candidate.typeName == "int") {
      score += 0.1;
    }

    // For local variables, give extra points
    if (!candidate.isGlobal) {
      score += 0.05;
    }

    // Prefer larger groups (more constants)
    score += std::min(0.15, group.constants.size() * 0.03);

    // Bonus for variables that have stores from constants
    if (candidate.hasStoresFromConst) {
      score += 0.15;
    }

    if (score > bestScore) {
      bestScore = score;
      bestGroup = group.id;
    }
  }

  // Lower the threshold for better recall (at cost of precision)
  if (bestScore < 0.25) {
    return "";
  }

  return bestGroup;
}

double FlagIdentifier::calculateGroupMatch(
    const std::set<int64_t> &assignedConsts,
    const ConstantGroup &group) const {

  if (assignedConsts.empty()) {
    return 0.0;
  }

  int matches = 0;
  auto groupValues = group.getValues();

  for (int64_t val : assignedConsts) {
    if (groupValues.count(val)) {
      matches++;
    }
  }

  // Ratio of assigned constants that are in the group
  double matchRatio = static_cast<double>(matches) / assignedConsts.size();

  // Prefer groups with multiple constants
  double sizeBonus = std::min(0.2, group.constants.size() * 0.05);

  return matchRatio + sizeBonus;
}

void FlagIdentifier::collectAssignments(
    Value *variable,
    Function *func,
    const std::set<int64_t> &groupValues,
    std::vector<AssignmentPoint> &outAssignments) {

  if (!variable || !func) return;

  for (auto *use : variable->users()) {
    if (!use) continue;
    if (auto *store = dyn_cast<StoreInst>(use)) {
      if (store->getPointerOperand() == variable) {
        Value *val = store->getValueOperand();
        int64_t constVal = 0;

        if (auto *ci = dyn_cast<ConstantInt>(val)) {
          constVal = ci->getSExtValue();

          // Only record assignments from group constants
          if (groupValues.empty() || groupValues.count(constVal)) {
            AssignmentPoint ap;
            ap.location = getSourceLocation(store);
            ap.assignedValue = constVal;
            ap.assignment = variable->getName().str() + " = " +
                           std::to_string(constVal);
            outAssignments.push_back(ap);
          }
        }
      }
    }
  }
}

void FlagIdentifier::collectChecks(
    Value *variable,
    Function *func,
    const std::set<int64_t> &groupValues,
    std::vector<CheckPoint> &outChecks) {

  if (!variable || !func) return;

  // Find all loads of this variable
  std::vector<LoadInst*> loads;
  for (auto *use : variable->users()) {
    if (!use) continue;
    if (auto *load = dyn_cast<LoadInst>(use)) {
      loads.push_back(load);
    }
  }

  // Check uses of each load
  for (auto *load : loads) {
    for (auto *loadUse : load->users()) {
      if (!loadUse) continue;

      if (auto *cmp = dyn_cast<ICmpInst>(loadUse)) {
        int64_t constVal = 0;
        CheckType checkType = CheckType::Equal;

        // Get the other operand (should be constant)
        Value *op0 = cmp->getOperand(0);
        Value *op1 = cmp->getOperand(1);

        Value *other = nullptr;
        if (op0 == load) {
          other = op1;
        } else if (op1 == load) {
          other = op0;
        }

        if (other && isa<ConstantInt>(other)) {
          constVal = cast<ConstantInt>(other)->getSExtValue();

          // Determine check type
          switch (cmp->getPredicate()) {
          case CmpInst::ICMP_EQ:
            checkType = CheckType::Equal;
            break;
          case CmpInst::ICMP_NE:
            checkType = CheckType::NotEqual;
            break;
          default:
            checkType = CheckType::Equal;
            break;
          }

          // Only record checks against group constants
          if (groupValues.empty() || groupValues.count(constVal)) {
            CheckPoint cp;
            cp.location = getSourceLocation(cmp);
            cp.checkType = checkType;
            cp.comparedValue = constVal;
            cp.condition = load->getName().str() +
                          (checkType == CheckType::Equal ? " == " : " != ") +
                          std::to_string(constVal);
            outChecks.push_back(cp);
          }
        }
      }

      // Check for bitwise operations
      if (auto *binOp = dyn_cast<BinaryOperator>(loadUse)) {
        if (binOp->getOpcode() == Instruction::And ||
            binOp->getOpcode() == Instruction::Or ||
            binOp->getOpcode() == Instruction::Xor) {

          Value *op0 = binOp->getOperand(0);
          Value *op1 = binOp->getOperand(1);

          Value *other = nullptr;
          CheckType checkType = CheckType::BitAnd;

          if (op0 == load) {
            other = op1;
          } else if (op1 == load) {
            other = op0;
          }

          if (other && isa<ConstantInt>(other)) {
            int64_t constVal = cast<ConstantInt>(other)->getSExtValue();

            if (groupValues.empty() || groupValues.count(constVal)) {
              CheckPoint cp;
              cp.location = getSourceLocation(binOp);
              cp.checkType = checkType;
              cp.comparedValue = constVal;

              std::string opStr;
              if (binOp->getOpcode() == Instruction::And) opStr = "&";
              else if (binOp->getOpcode() == Instruction::Or) opStr = "|";
              else opStr = "^";

              cp.condition = load->getName().str() + " " + opStr + " " +
                            std::to_string(constVal);
              outChecks.push_back(cp);
            }
          }
        }
      }

      // Check for switch statements
      if (config.trackSwitchCases) {
        if (auto *switchInst = dyn_cast<SwitchInst>(loadUse)) {
          for (auto &caseIt : switchInst->cases()) {
            int64_t caseVal = caseIt.getCaseValue()->getSExtValue();

            if (groupValues.empty() || groupValues.count(caseVal)) {
              CheckPoint cp;
              cp.location = getSourceLocation(switchInst);
              cp.checkType = CheckType::Switch;
              cp.comparedValue = caseVal;
              cp.condition = "switch(" + load->getName().str() + ") case " +
                             std::to_string(caseVal);
              outChecks.push_back(cp);
            }
          }
        }
      }
    }
  }
}

void FlagIdentifier::analyzeVariable(
    Value *variable,
    const VarCandidate &candidate,
    const std::vector<ConstantGroup> &groups,
    VarAnalysisContext &outContext) {

  // Match to group
  outContext.matchedGroupId = matchToGroup(candidate, groups);

  // Get group values if matched
  std::set<int64_t> groupValues;
  if (!outContext.matchedGroupId.empty()) {
    for (const auto &g : groups) {
      if (g.id == outContext.matchedGroupId) {
        groupValues = g.getValues();
        break;
      }
    }
  }

  // Find function containing this variable
  Function *func = nullptr;
  Module *module = nullptr;

  if (variable) {
    if (auto *inst = dyn_cast<Instruction>(variable)) {
      func = inst->getFunction();
      if (func) module = func->getParent();
    } else if (auto *gv = dyn_cast<GlobalVariable>(variable)) {
      module = gv->getParent();
    }
  }

  // Collect assignments and checks - only if we have valid module
  if (func && variable && module) {
    collectAssignments(variable, func, groupValues, outContext.assignments);
    collectChecks(variable, func, groupValues, outContext.checks);
  }

  // For globals, analyze all uses in all functions
  if (candidate.isGlobal && module && variable) {
    for (auto &f : *module) {
      collectAssignments(variable, &f, groupValues, outContext.assignments);
      collectChecks(variable, &f, groupValues, outContext.checks);
    }
  }
}

SourceLocation FlagIdentifier::getSourceLocation(Instruction *inst) const {
  SourceLocation loc("<unknown>", 0);

  if (inst) {
    DebugLoc dl = inst->getDebugLoc();
    if (dl) {
      loc.file = dl->getFilename().str();
      loc.line = dl->getLine();
      loc.column = dl->getColumn();
    }
  }

  return loc;
}

//===----------------------------------------------------------------------===//
// JSONReporter Implementation
//===----------------------------------------------------------------------===//

std::string JSONReporter::generateJSON(const AnalysisResult &result) {
  std::ostringstream json;

  json << "{\n";
  json << "  \"constantGroups\": [\n";

  for (size_t i = 0; i < result.constantGroups.size(); ++i) {
    json << "    " << constantGroupToJSON(result.constantGroups[i]);
    if (i < result.constantGroups.size() - 1) {
      json << ",";
    }
    json << "\n";
  }

  json << "  ],\n";
  json << "  \"flagVariables\": [\n";

  for (size_t i = 0; i < result.flagVariables.size(); ++i) {
    json << "    " << flagVariableToJSON(result.flagVariables[i]);
    if (i < result.flagVariables.size() - 1) {
      json << ",";
    }
    json << "\n";
  }

  json << "  ],\n";
  json << "  \"stats\": {\n";
  json << "    \"totalConstants\": " << result.stats.totalConstants << ",\n";
  json << "    \"totalGroups\": " << result.stats.totalGroups << ",\n";
  json << "    \"totalVariables\": " << result.stats.totalVariables << ",\n";
  json << "    \"filteredInputVars\": " << result.stats.filteredInputVars << ",\n";
  json << "    \"filteredArithmeticVars\": " << result.stats.filteredArithmeticVars << "\n";
  json << "  }\n";
  json << "}\n";

  return json.str();
}

bool JSONReporter::writeToFile(const AnalysisResult &result,
                               const std::string &outputPath) {
  std::ofstream file(outputPath);
  if (!file.is_open()) {
    return false;
  }

  file << generateJSON(result);
  file.close();

  return true;
}

std::string JSONReporter::constantGroupToJSON(const ConstantGroup &group) {
  std::ostringstream json;

  json << "{\n";
  json << "      \"id\": \"" << escapeJSON(group.id) << "\",\n";
  json << "      \"commonPrefix\": \"" << escapeJSON(group.commonPrefix) << "\",\n";
  json << "      \"type\": \"" << (group.type == ConstantType::Enum ? "enum" :
                                   group.type == ConstantType::Macro ? "macro" : "const") << "\",\n";
  json << "      \"location\": \"" << escapeJSON(group.location.toString()) << "\",\n";
  json << "      \"constants\": [\n";

  for (size_t i = 0; i < group.constants.size(); ++i) {
    const auto &c = group.constants[i];
    json << "        {";
    json << "\"name\": \"" << escapeJSON(c.name) << "\", ";
    json << "\"value\": " << c.value << ", ";
    json << "\"location\": \"" << escapeJSON(c.location.toString()) << "\"";
    json << "}";
    if (i < group.constants.size() - 1) {
      json << ",";
    }
    json << "\n";
  }

  json << "      ]\n";
  json << "    }";

  return json.str();
}

std::string JSONReporter::flagVariableToJSON(const FlagVariable &flag) {
  std::ostringstream json;

  json << "{\n";
  json << "      \"name\": \"" << escapeJSON(flag.name) << "\",\n";
  json << "      \"type\": \"" << escapeJSON(flag.typeName) << "\",\n";
  json << "      \"function\": \"" << escapeJSON(flag.function) << "\",\n";
  json << "      \"location\": \"" << escapeJSON(flag.location.toString()) << "\",\n";
  json << "      \"groupId\": \"" << escapeJSON(flag.groupId) << "\",\n";
  json << "      \"confidence\": " << std::fixed << std::setprecision(2)
       << flag.confidence << ",\n";
  json << "      \"assignments\": [";

  for (size_t i = 0; i < flag.assignments.size(); ++i) {
    const auto &a = flag.assignments[i];
    json << "{";
    json << "\"location\": \"" << escapeJSON(a.location.toString()) << "\", ";
    json << "\"value\": " << a.assignedValue;
    json << "}";
    if (i < flag.assignments.size() - 1) {
      json << ", ";
    }
  }

  json << "],\n";
  json << "      \"checks\": [";

  for (size_t i = 0; i < flag.checks.size(); ++i) {
    const auto &c = flag.checks[i];
    json << "{";
    json << "\"location\": \"" << escapeJSON(c.location.toString()) << "\", ";
    json << "\"type\": \"" << (c.checkType == CheckType::Equal ? "equal" :
                              c.checkType == CheckType::NotEqual ? "not_equal" :
                              c.checkType == CheckType::BitAnd ? "bit_and" :
                              c.checkType == CheckType::BitOr ? "bit_or" : "switch") << "\", ";
    json << "\"value\": " << c.comparedValue;
    json << "}";
    if (i < flag.checks.size() - 1) {
      json << ", ";
    }
  }

  json << "]\n";
  json << "    }";

  return json.str();
}

std::string JSONReporter::escapeJSON(const std::string &str) {
  std::string result;
  result.reserve(str.length() * 1.2);

  for (char c : str) {
    switch (c) {
    case '"':  result += "\\\""; break;
    case '\\': result += "\\\\"; break;
    case '\b': result += "\\b"; break;
    case '\f': result += "\\f"; break;
    case '\n': result += "\\n"; break;
    case '\r': result += "\\r"; break;
    case '\t': result += "\\t"; break;
    default:
      if (c < 32) {
        char buf[8];
        snprintf(buf, sizeof(buf), "\\u%04x", c);
        result += buf;
      } else {
        result += c;
      }
    }
  }

  return result;
}

//===----------------------------------------------------------------------===//
// MarkdownReporter Implementation
//===----------------------------------------------------------------------===//

std::string MarkdownReporter::generateReport(const AnalysisResult &result) {
  std::ostringstream md;

  md << "# Flag Variable Recognition Report\n\n";
  md << "## Summary\n\n";
  md << generateStats(result.stats, result.flagVariables.size());
  md << "\n";

  md << "## Flag Variables\n\n";
  md << generateFlagDetails(result.flagVariables);

  md << "\n## Notes\n\n";
  md << "- **Conservative Analysis**: This tool uses conservative heuristics to identify flag variables.\n";
  md << "- **False Positives**: Some variables may be incorrectly flagged due to shared naming patterns.\n";
  md << "- **False Negatives**: Some flag variables may be missed if they don't match expected patterns.\n";
  md << "- **Confidence Score**: Values range from 0.0 to 1.0, higher values indicate stronger evidence.\n";

  return md.str();
}

bool MarkdownReporter::writeToFile(const AnalysisResult &result,
                                   const std::string &outputPath) {
  std::ofstream file(outputPath);
  if (!file.is_open()) {
    return false;
  }

  file << generateReport(result);
  file.close();

  return true;
}

std::string MarkdownReporter::generateStats(const AnalysisResult::Stats &stats, size_t flagCount) {
  std::ostringstream md;

  md << "| Metric | Count |\n";
  md << "|--------|-------|\n";
  md << "| Total Constants | " << stats.totalConstants << " |\n";
  md << "| Total Groups | " << stats.totalGroups << " |\n";
  md << "| Total Variables Analyzed | " << stats.totalVariables << " |\n";
  md << "| Input-Related Filtered | " << stats.filteredInputVars << " |\n";
  md << "| Arithmetic Variables Filtered | " << stats.filteredArithmeticVars << " |\n";
  md << "| Flag Variables Identified | " << flagCount << " |\n";

  return md.str();
}

std::string MarkdownReporter::generateFlagDetails(
    const std::vector<FlagVariable> &flags) {

  std::ostringstream md;

  if (flags.empty()) {
    md << "No flag variables identified.\n";
    return md.str();
  }

  for (const auto &flag : flags) {
    md << "### " << flag.name << "\n\n";
    md << "- **Type**: `" << flag.typeName << "`\n";
    md << "- **Function**: `" << flag.function << "`\n";
    md << "- **Location**: " << flag.location.toString() << "\n";
    md << "- **Confidence**: " << std::fixed << std::setprecision(2)
       << (flag.confidence * 100) << "%\n";
    md << "- **Group ID**: `" << flag.groupId << "`\n";

    if (!flag.assignments.empty()) {
      md << "\n**Assignment Points**:\n";
      for (const auto &a : flag.assignments) {
        md << "  - " << a.location.toString() << ": `"
           << a.assignment << "`\n";
      }
    }

    if (!flag.checks.empty()) {
      md << "\n**Check Points**:\n";
      for (const auto &c : flag.checks) {
        md << "  - " << c.location.toString() << ": `"
           << c.condition << "`\n";
      }
    }

    md << "\n";
  }

  return md.str();
}

} // namespace flagrec
