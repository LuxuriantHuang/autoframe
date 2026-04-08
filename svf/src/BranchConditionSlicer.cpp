// BranchConditionSlicer.cpp
// Standalone LLVM/SVF slicer.
// Based on BranchConditionSlicer_IR.cpp with enhanced output formatting
//
// 功能：
//  1) -slice-loc="file:line" 定位指令
//     - 如果指令是 if/elseif/switch 分支：以分支条件变量为种子做后向切片
//     - 如果指令不是分支：以该指令包含的所有操作数（包括函数参数）为种子做后向切片
//  2) 后向切片基于数据依赖
//  3) 可选加入控制依赖（PostDominatorTree 控制依赖）
//  4) 输出：
//     - 命中目标、IR slice 等：输出到命令行 (errs)
//     - Source Slice：如果指定 -slice-out=xxx.txt，则仅把 Source Slice 输出到该文件
//  5) 【增强】输出的 slice 结果（IR Slice / Source Slice）均带上对应函数名
//
// 增强功能（借鉴 AutoBug 的切片输出，默认启用）：
//  - 改进1: Gap 标记 - 当跳过的行数超过3行时，用 /*...N lines omitted...*/ 标记
//  - 改进2: 函数边界保留 - 自动包含函数签名和 { } 边界
//  - 改进3: 代码块格式 - 输出完整代码块格式，目标行用 ">>>" 前缀标记
//  - 改进4: 瓶颈点 assert - 在目标分支位置插入 assert(!condition) 标记
//           选项: -slice-assert=true/false (默认true)
//           选项: -slice-assert-negate=true/false (默认true，即 assert(!cond))
//           选项: -slice-assert-prefix="assert" (默认，可改为 __CPROVER_assert 等)
//
// Run:
//   BranchConditionSlicer input.bc \
//       -slice-loc="parse.c:8975" \
//       -slice-cd=true \
//       -slice-src=true \
//       -slice-src-context=2 \
//       -slice-assert=true \
//       -slice-out="slice_src.txt"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/BasicAliasAnalysis.h"
#include "llvm/Analysis/MemoryDependenceAnalysis.h"
#include "llvm/Analysis/PhiValues.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include "Graphs/PAG.h"
#include "Graphs/PTACallGraph.h"
#include "Graphs/ICFGNode.h"
#include "SVF-FE/LLVMModule.h"
#include "SVF-FE/PAGBuilder.h"
#include "Util/SVFUtil.h"
#include "WPA/Andersen.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace llvm;

/* ===================== options ===================== */

static cl::opt<std::string>
    SliceLoc("slice-loc",
             cl::desc("Target source location file:line (e.g., parse.c:8975)"),
             cl::init(""));

static cl::opt<std::string>
    SliceCaseLoc("slice-case-loc",
                 cl::desc("Original switch case source location file:line when -slice-loc points at the parent switch"),
                 cl::init(""));

static cl::opt<std::string>
    InputBitcode(cl::Positional, cl::desc("<input .ll or .bc>"), cl::Required);

static cl::opt<unsigned>
    SearchSuccSteps("slice-succ-steps",
                    cl::desc("How many successor steps to search for a nearby br/switch"),
                    cl::init(2));

static cl::opt<bool>
    PrintIRSlice("slice-print",
                 cl::desc("Print IR sliced instructions to cmd"),
                 cl::init(true));

static cl::opt<unsigned>
    MaxIRSliceInsts("slice-max",
                    cl::desc("Max IR slice instructions to print (0 = no limit)"),
                    cl::init(0));

static cl::opt<bool>
    IncludeControlDep("slice-cd",
                      cl::desc("Include control dependence (postdom-based)"),
                      cl::init(true));

static cl::opt<unsigned>
    ControlDepDepth("slice-cd-depth",
                    cl::desc("Max fixed-point rounds when expanding control dependence"),
                    cl::init(1));

static cl::opt<bool>
    PrintSourceSlice("slice-src",
                     cl::desc("Generate source slice"),
                     cl::init(true));

static cl::opt<unsigned>
    SourceContext("slice-src-context",
                  cl::desc("Context lines around each source line in slice"),
                  cl::init(0));

static cl::opt<std::string>
    SourceOut("slice-out",
              cl::desc("Write ONLY Source Slice to this file (other output stays in cmd)"),
              cl::init(""));

// ============== v2 新增功能（默认启用）==============
namespace V2Config {
  // Gap 标记：跳过3行以上时插入 /*...N lines omitted...*/
  constexpr unsigned GapThreshold = 3;
  // 函数边界保留：自动包含函数签名和 { }
  constexpr bool KeepFuncBoundary = true;
  // 代码块格式：完整代码块格式，目标行用 >>> 标记
  constexpr bool CodeBlockFormat = true;
}

// ============== v2 新增选项：瓶颈点 assert（命令行控制）==============
static cl::opt<bool>
    InsertAssert("slice-assert",
                 cl::desc("Insert assert(!condition) at target branch location"),
                 cl::init(true));

static cl::opt<bool>
    AssertNegate("slice-assert-negate",
                 cl::desc("Negate condition in assert (assert(!cond) vs assert(cond))"),
                 cl::init(true));

static cl::opt<std::string>
    BranchCoverage("slice-branch-cover",
                   cl::desc("Desired branch coverage polarity: true | false | auto"),
                   cl::init("auto"));

static cl::opt<std::string>
    AssertPrefix("slice-assert-prefix",
                 cl::desc("Prefix for assert statement (e.g., '__CPROVER_assert' for CBMC)"),
                 cl::init("assert"));

static cl::opt<bool>
    UseSVFCallPath("slice-svf-callpath",
                   cl::desc("Augment slice with an SVF entry-to-bottleneck call path"),
                   cl::init(false));

static cl::opt<bool>
    MergeSVFCallPathIntoSource("slice-merge-callpath-src",
                               cl::desc("Merge SVF entry path into Source Slice"),
                               cl::init(false));

static cl::opt<std::string>
    SliceTargetKind("slice-target-kind",
                    cl::desc("Target selection mode: auto | branch | switch-case | stmt"),
                    cl::init("auto"));

static cl::opt<std::string>
    SliceEntryFunction("slice-entry",
                       cl::desc("Program entry function used for SVF call-path search"),
                       cl::init("main"));

static cl::opt<bool>
    IncludeSourceTypeInfo("slice-src-types",
                          cl::desc("Augment Source Slice with debug-driven struct type definitions"),
                          cl::init(false));

/* ===================== helpers ===================== */

// 存储目标分支的条件信息
struct TargetBranchInfo {
  unsigned Line;
  std::string File;
  std::string Condition;  // 条件表达式（从源码提取）
  std::string CaseValue;  // switch/case 的目标 case 值
  unsigned CaseLine = 0;  // switch/case 的目标 case 行
  bool IsBranch;          // 是否是分支指令
  bool IsSwitch;          // 是否是 switch
};
using TargetBranchMap = std::map<std::string, std::map<unsigned, TargetBranchInfo>>;

struct FunctionSourceLoc {
  std::string File;
  unsigned Line = 0;
};

struct CallPathStep {
  const Function *Caller = nullptr;
  const Function *Callee = nullptr;
  const Instruction *CallSite = nullptr;
  bool IsIndirect = false;
};

struct CallPathResult {
  bool Available = false;
  bool Reached = false;
  std::string EntryName;
  std::string Error;
  std::vector<CallPathStep> Steps;
};

struct OrderedFunctionView {
  std::string File;
  unsigned Line = 0;
  std::string Name;
};

namespace {

struct TargetLoc {
  std::string File;
  unsigned Line = 0;
};

enum class TargetKind {
  Auto,
  Branch,
  SwitchCase,
  Stmt,
};

static std::optional<TargetLoc> parseLoc(StringRef S) {
  if (S.empty()) return std::nullopt;
  auto Pos = S.rfind(':');
  if (Pos == StringRef::npos) return std::nullopt;

  StringRef File = S.substr(0, Pos);
  StringRef LineStr = S.substr(Pos + 1);
  if (File.empty() || LineStr.empty()) return std::nullopt;

  unsigned Line = 0;
  for (char c : LineStr) {
    if (!std::isdigit(static_cast<unsigned char>(c)))
      return std::nullopt;
    Line = Line * 10 + (c - '0');
  }
  if (Line == 0) return std::nullopt;

  return TargetLoc{File.str(), Line};
}

static TargetKind parseTargetKind(StringRef S) {
  if (S.equals_lower("branch"))
    return TargetKind::Branch;
  if (S.equals_lower("switch-case"))
    return TargetKind::SwitchCase;
  if (S.equals_lower("stmt"))
    return TargetKind::Stmt;
  return TargetKind::Auto;
}

static bool isAbsPath(StringRef P) {
  if (P.empty()) return false;
  if (P.startswith("/")) return true;
  if (P.size() >= 2 && std::isalpha((unsigned char)P[0]) && P[1] == ':') return true;
  return false;
}

static std::string joinPath(StringRef Dir, StringRef File) {
  if (Dir.empty()) return File.str();
  if (File.empty()) return Dir.str();
  std::string D = Dir.str();
  if (!D.empty() && D.back() != '/' && D.back() != '\\')
    D.push_back('/');
  return D + File.str();
}

static bool fileNameMatches(StringRef DbgFile, StringRef TargetFile) {
  if (DbgFile == TargetFile) return true;

  auto baseName = [](StringRef Path) -> StringRef {
    size_t slash = Path.find_last_of("/\\");
    if (slash == StringRef::npos) return Path;
    return Path.substr(slash + 1);
  };

  StringRef DbgBase = baseName(DbgFile);
  StringRef TgtBase = baseName(TargetFile);
  if (DbgBase == TgtBase) return true;

  if (DbgFile.contains(TargetFile) || TargetFile.contains(DbgFile)) return true;
  if (DbgBase.contains(TgtBase) || TgtBase.contains(DbgBase)) return true;

  return false;
}

/* ===== debug loc collection: current + inlinedAt chain ===== */

static void collectAllSourceLocations(const Instruction &I,
                                      SmallVectorImpl<std::pair<std::string, unsigned>> &Out) {
  DebugLoc DL = I.getDebugLoc();
  if (!DL) return;

  const DILocation *Loc = DL.get();
  while (Loc) {
    const DIScope *Scope = dyn_cast_or_null<DIScope>(Loc->getScope());
    if (Scope) {
      const DIFile *F = Scope->getFile();
      if (F) {
        StringRef FN = F->getFilename();
        StringRef DIR = F->getDirectory();
        std::string Path;

        if (!FN.empty()) {
          if (isAbsPath(FN)) Path = FN.str();
          else if (!DIR.empty()) Path = joinPath(DIR, FN);
          else Path = FN.str();
        }

        unsigned Line = Loc->getLine();
        if (!Path.empty() && Line != 0)
          Out.emplace_back(Path, Line);
      } else {
        // fallback: filename only
        StringRef FN = Scope->getFilename();
        unsigned Line = Loc->getLine();
        if (!FN.empty() && Line != 0)
          Out.emplace_back(FN.str(), Line);
      }
    }
    Loc = Loc->getInlinedAt();
  }
}

static bool instMatchesTarget(const Instruction &I, const TargetLoc &T) {
  SmallVector<std::pair<std::string, unsigned>, 4> Locs;
  collectAllSourceLocations(I, Locs);
  for (auto &FL : Locs) {
    if (FL.second == T.Line && fileNameMatches(FL.first, T.File))
      return true;
  }
  return false;
}

static std::optional<std::pair<std::string, unsigned>>
getPrimaryFileLine(const Instruction &I) {
  DebugLoc DL = I.getDebugLoc();
  if (!DL) return std::nullopt;

  const DILocation *Loc = DL.get();
  if (!Loc) return std::nullopt;

  const DIScope *Scope = dyn_cast_or_null<DIScope>(Loc->getScope());
  if (!Scope) return std::nullopt;

  const DIFile *F = Scope->getFile();
  StringRef FN, DIR;
  if (F) {
    FN = F->getFilename();
    DIR = F->getDirectory();
  } else {
    FN = Scope->getFilename();
  }

  unsigned Line = Loc->getLine();
  if (FN.empty() || Line == 0) return std::nullopt;

  std::string Path;
  if (isAbsPath(FN)) Path = FN.str();
  else if (!DIR.empty()) Path = joinPath(DIR, FN);
  else Path = FN.str();

  return std::make_pair(Path, Line);
}

static std::optional<FunctionSourceLoc> getFunctionSourceLoc(const Function &F) {
  if (const DISubprogram *SP = F.getSubprogram()) {
    StringRef FN = SP->getFilename();
    StringRef DIR = SP->getDirectory();
    unsigned Line = SP->getLine();
    if (!FN.empty() && Line != 0) {
      std::string Path;
      if (isAbsPath(FN)) Path = FN.str();
      else if (!DIR.empty()) Path = joinPath(DIR, FN);
      else Path = FN.str();
      return FunctionSourceLoc{Path, Line};
    }
  }

  for (const BasicBlock &BB : F) {
    for (const Instruction &I : BB) {
      if (auto Loc = getPrimaryFileLine(I))
        return FunctionSourceLoc{Loc->first, Loc->second};
    }
  }
  return std::nullopt;
}

/* ===================== printing helpers (with function name) ===================== */

static void printInstWithLoc(raw_ostream &OS, const Instruction *I) {
  OS << "  ";
  if (const Function *F = I->getFunction())
    OS << "[func=" << F->getName() << "] ";

  if (auto Loc = getPrimaryFileLine(*I)) {
    OS << Loc->first << ":" << Loc->second << "  ";
  } else {
    OS << "<no-dbg>  ";
  }
  OS << *I << "\n";
}

/* ===================== pointer base helpers ===================== */

static const Value *stripCastsAndGEPs(const Value *V) {
  while (true) {
    if (auto *BC = dyn_cast<BitCastOperator>(V)) {
      V = BC->getOperand(0);
      continue;
    }
    if (auto *Op = dyn_cast<Operator>(V)) {
      if (Op->getOpcode() == Instruction::AddrSpaceCast) {
        V = Op->getOperand(0);
        continue;
      }
    }
    if (auto *GEP = dyn_cast<GEPOperator>(V)) {
      V = GEP->getPointerOperand();
      continue;
    }
    break;
  }
  return V;
}

static bool sameBasePointer(const Value *A, const Value *B) {
  A = stripCastsAndGEPs(A);
  B = stripCastsAndGEPs(B);
  return A == B;
}

static const AllocaInst *getTrackedStackSlot(const Value *Ptr) {
  return dyn_cast<AllocaInst>(stripCastsAndGEPs(Ptr));
}

/* ===================== data slicing ===================== */

struct SliceResult {
  SmallVector<const Instruction *, 256> Insts; // discovery order
  DenseSet<const Instruction *> InstSet;
};

struct FunctionMemoryAnalysisContext {
  DominatorTree DT;
  AssumptionCache AC;
  TargetLibraryInfoImpl TLII;
  TargetLibraryInfo TLI;
  PhiValues PV;
  BasicAAResult BAA;
  AAResults AA;
  MemoryDependenceResults MemDep;

  explicit FunctionMemoryAnalysisContext(Function &F)
      : DT(F),
        AC(F),
        TLII(Triple(F.getParent() ? F.getParent()->getTargetTriple() : "")),
        TLI(TLII, &F),
        PV(F),
        BAA(F.getParent()->getDataLayout(), F, TLI, AC, &DT, nullptr, &PV),
        AA(TLI),
        MemDep(AA, AC, TLI, DT, PV, /*DefaultBlockScanLimit=*/200) {
    AA.addAAResult(BAA);
  }
};

static void addInst(SliceResult &R, const Instruction *I) {
  if (!I) return;
  if (R.InstSet.insert(I).second)
    R.Insts.push_back(I);
}

static const Instruction *findDefiningMemoryInstApprox(const LoadInst *LI,
                                                       unsigned MaxPredHops = 128) {
  const Value *LoadPtr  = LI->getPointerOperand();
  const Value *LoadBase = stripCastsAndGEPs(LoadPtr);

  const BasicBlock *BB = LI->getParent();

  // same BB: scan backwards
  for (auto It = LI->getIterator(); It != BB->begin();) {
    --It;
    if (auto *SI = dyn_cast<StoreInst>(&*It)) {
      const Value *StorePtr = SI->getPointerOperand();
      if (sameBasePointer(LoadBase, StorePtr))
        return SI;
    }
  }

  // predecessors (bounded)
  SmallVector<const BasicBlock *, 64> Q;
  DenseSet<const BasicBlock *> Seen;
  Q.push_back(BB);
  Seen.insert(BB);

  unsigned Hops = 0;
  while (!Q.empty() && Hops++ < MaxPredHops) {
    const BasicBlock *Cur = Q.pop_back_val();
    for (const BasicBlock *Pred : predecessors(Cur)) {
      if (!Seen.insert(Pred).second)
        continue;

      for (auto It = Pred->rbegin(); It != Pred->rend(); ++It) {
        if (auto *SI = dyn_cast<StoreInst>(&*It)) {
          const Value *StorePtr = SI->getPointerOperand();
          if (sameBasePointer(LoadBase, StorePtr))
            return SI;
        }
      }
      Q.push_back(Pred);
    }
  }

  return nullptr;
}

static FunctionMemoryAnalysisContext &
getFunctionMemoryContext(Function &F,
                         DenseMap<const Function *, std::unique_ptr<FunctionMemoryAnalysisContext>> &Cache) {
  auto It = Cache.find(&F);
  if (It != Cache.end())
    return *It->second;

  auto Inserted = Cache.try_emplace(&F, std::make_unique<FunctionMemoryAnalysisContext>(F));
  return *Inserted.first->second;
}

static const Instruction *
findDefiningMemoryInst(const LoadInst *LI,
                       DenseMap<const Function *, std::unique_ptr<FunctionMemoryAnalysisContext>> &MemCtxCache) {
  const Function *F = LI->getFunction();
  if (!F)
    return findDefiningMemoryInstApprox(LI);

  auto &Ctx = getFunctionMemoryContext(*const_cast<Function *>(F), MemCtxCache);
  MemDepResult Dep = Ctx.MemDep.getDependency(const_cast<LoadInst *>(LI));
  if (Instruction *DepI = Dep.getInst()) {
    if (isa<StoreInst>(DepI) || isa<LoadInst>(DepI) || isa<AllocaInst>(DepI) ||
        isa<Argument>(DepI))
      return DepI;
    return DepI;
  }

  return findDefiningMemoryInstApprox(LI);
}

static SmallVector<const StoreInst *, 8>
findLocalStackStores(const LoadInst *LI) {
  SmallVector<const StoreInst *, 8> Stores;
  const AllocaInst *Slot = getTrackedStackSlot(LI->getPointerOperand());
  const Function *F = LI->getFunction();
  if (!Slot || !F)
    return Stores;

  for (const BasicBlock &BB : *F) {
    for (const Instruction &I : BB) {
      const auto *SI = dyn_cast<StoreInst>(&I);
      if (!SI)
        continue;
      if (!sameBasePointer(SI->getPointerOperand(), Slot))
        continue;
      Stores.push_back(SI);
    }
  }

  return Stores;
}

static void backwardSliceValue(const Value *Seed,
                               SliceResult &Out,
                               DenseSet<const Value*> &SeenValues,
                               DenseMap<const Function *, std::unique_ptr<FunctionMemoryAnalysisContext>> &MemCtxCache) {
  if (!Seed) return;
  if (!SeenValues.insert(Seed).second) return;

  if (auto *I = dyn_cast<Instruction>(Seed)) {
    addInst(Out, I);

    if (auto *LI = dyn_cast<LoadInst>(I)) {
      backwardSliceValue(LI->getPointerOperand(), Out, SeenValues, MemCtxCache);

      if (const Instruction *Def = findDefiningMemoryInst(LI, MemCtxCache)) {
        addInst(Out, Def);
        if (const auto *SI = dyn_cast<StoreInst>(Def)) {
          backwardSliceValue(SI->getValueOperand(), Out, SeenValues, MemCtxCache);
          backwardSliceValue(SI->getPointerOperand(), Out, SeenValues, MemCtxCache);
        } else if (const auto *DefLI = dyn_cast<LoadInst>(Def)) {
          backwardSliceValue(DefLI->getPointerOperand(), Out, SeenValues, MemCtxCache);
        }
      }

      for (const StoreInst *SI : findLocalStackStores(LI)) {
        addInst(Out, SI);
        backwardSliceValue(SI->getValueOperand(), Out, SeenValues, MemCtxCache);
        backwardSliceValue(SI->getPointerOperand(), Out, SeenValues, MemCtxCache);
      }
    }

    if (auto *CB = dyn_cast<CallBase>(I)) {
      for (const Value *Arg : CB->args())
        backwardSliceValue(Arg, Out, SeenValues, MemCtxCache);
    }

    for (const Use &U : I->operands())
      backwardSliceValue(U.get(), Out, SeenValues, MemCtxCache);

    return;
  }

  if (isa<Argument>(Seed) || isa<GlobalValue>(Seed) || isa<Constant>(Seed)) return;

  if (auto *Op = dyn_cast<Operator>(Seed)) {
    for (const Value *Sub : Op->operands())
      backwardSliceValue(Sub, Out, SeenValues, MemCtxCache);
  }
}

/* ===================== branch locating ===================== */

static bool isBranchOrSwitch(const Instruction *I) {
  return isa<BranchInst>(I) || isa<SwitchInst>(I);
}

// Find all switch instructions in the module with their location info
struct SwitchInfo {
  const SwitchInst *SI;
  std::string File;
  unsigned SwitchLine;
  unsigned EndLine; // Actual end line determined from code
};

// Find the actual end line of a switch by analyzing all its successors
static unsigned findSwitchEndLine(const SwitchInst *SI, const std::string &SwitchFile) {
  unsigned MaxLine = 0;
  unsigned SwitchLine = 0;

  if (auto Loc = getPrimaryFileLine(*SI)) {
    SwitchLine = Loc->second;
    MaxLine = SwitchLine;
  }

  // Collect all reachable basic blocks from the switch
  // This includes all case blocks and the default block
  SmallPtrSet<const BasicBlock*, 32> Visited;
  SmallVector<const BasicBlock*, 32> WorkList;

  const BasicBlock *SwitchBB = SI->getParent();
  WorkList.push_back(SwitchBB);
  Visited.insert(SwitchBB);

  // Track the depth to avoid infinite loops
  DenseMap<const BasicBlock*, unsigned> Depth;
  Depth[SwitchBB] = 0;

  while (!WorkList.empty()) {
    const BasicBlock *BB = WorkList.pop_back_val();
    unsigned CurrentDepth = Depth[BB];

    // Limit depth to avoid analyzing too far (heuristic: switch bodies usually <= 100 blocks deep)
    if (CurrentDepth > 100) continue;

    // Check all instructions in this block for debug locations
    for (const Instruction &I : *BB) {
      if (auto Loc = getPrimaryFileLine(I)) {
        if (fileNameMatches(Loc->first, SwitchFile)) {
          MaxLine = std::max(MaxLine, Loc->second);
        }
      }
    }

    // Add successors to work list
    for (const BasicBlock *Succ : successors(BB)) {
      if (Visited.insert(Succ).second) {
        Depth[Succ] = CurrentDepth + 1;
        WorkList.push_back(Succ);
      }
    }
  }

  // Also check if we can find the post-dominator (where all cases merge)
  // The merge point is a good indication of switch end
  const Function *F = SwitchBB->getParent();
  if (!F) return MaxLine;

  // Try to find a common post-dominator using simple heuristic
  // Look for blocks that are reachable from multiple case successors
  SmallPtrSet<const BasicBlock*, 16> CaseBlocks;
  for (unsigned i = 0; i < SI->getNumSuccessors(); ++i) {
    CaseBlocks.insert(SI->getSuccessor(i));
  }

  // Find blocks that have multiple case block predecessors
  for (const BasicBlock &BB : *F) {
    unsigned CasePredCount = 0;
    for (const BasicBlock *Pred : predecessors(&BB)) {
      if (CaseBlocks.count(Pred)) {
        CasePredCount++;
      }
    }

    // If this block is reached by multiple case blocks, it's likely the merge point
    if (CasePredCount >= 2) {
      for (const Instruction &I : BB) {
        if (auto Loc = getPrimaryFileLine(I)) {
          if (fileNameMatches(Loc->first, SwitchFile)) {
            MaxLine = std::max(MaxLine, Loc->second);
          }
        }
      }
      // Check a few instructions ahead in the merge block for end line
      unsigned InstCount = 0;
      for (const Instruction &I : BB) {
        if (auto Loc = getPrimaryFileLine(I)) {
          if (fileNameMatches(Loc->first, SwitchFile)) {
            MaxLine = std::max(MaxLine, Loc->second);
          }
        }
        if (++InstCount > 5) break; // Only check first 5 instructions in merge block
      }
      break; // Found merge point
    }
  }

  return MaxLine;
}

static SmallVector<SwitchInfo, 16> findAllSwitches(Module &M) {
  SmallVector<SwitchInfo, 16> Switches;

  for (Function &F : M) {
    if (F.isDeclaration()) continue;

    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (const auto *SI = dyn_cast<SwitchInst>(&I)) {
          if (auto Loc = getPrimaryFileLine(I)) {
            SwitchInfo Info;
            Info.SI = SI;
            Info.File = Loc->first;
            Info.SwitchLine = Loc->second;
            // Find actual end line by analyzing switch body
            Info.EndLine = findSwitchEndLine(SI, Info.File);
            Switches.push_back(Info);
          }
        }
      }
    }
  }

  return Switches;
}

// Check if a line is within a switch's range (for case labels without instructions)
static const SwitchInst* findSwitchContainingLine(const SmallVector<SwitchInfo, 16> &Switches,
                                                   const TargetLoc &T) {
  for (const auto &Info : Switches) {
    if (fileNameMatches(Info.File, T.File)) {
      // Check if the target line is within this switch's range
      if (T.Line >= Info.SwitchLine && T.Line <= Info.EndLine) {
        return Info.SI;
      }
    }
  }
  return nullptr;
}

// Check if an instruction is inside a switch case block and return the parent switch
// A case block is a successor of a switch's basic block
static const SwitchInst* findParentSwitchForCase(const Instruction *I) {
  if (!I) return nullptr;

  const BasicBlock *BB = I->getParent();
  if (!BB) return nullptr;

  // Method 1: Check all predecessors to see if any has a switch terminator
  for (const BasicBlock *Pred : predecessors(BB)) {
    if (const Instruction *Term = Pred->getTerminator()) {
      if (const auto *SI = dyn_cast<SwitchInst>(Term)) {
        return SI;
      }
    }
  }

  // Also check the current BB - might be the switch block itself
  if (const Instruction *Term = BB->getTerminator()) {
    if (const auto *SI = dyn_cast<SwitchInst>(Term)) {
      return SI;
    }
  }

  // Method 2: choose the nearest same-function switch whose block dominates the
  // current block. This is more stable than guessing from lexical block lines.
  const Function *F = I->getFunction();
  if (!F)
    return nullptr;

  auto TargetLoc = getPrimaryFileLine(*I);
  DominatorTree DT(*const_cast<Function *>(F));
  const SwitchInst *Best = nullptr;
  unsigned BestDistance = std::numeric_limits<unsigned>::max();

  for (const BasicBlock &FuncBB : *F) {
    const auto *SI = dyn_cast<SwitchInst>(FuncBB.getTerminator());
    if (!SI)
      continue;
    if (!DT.dominates(SI->getParent(), BB))
      continue;

    auto SwitchLoc = getPrimaryFileLine(*SI);
    if (TargetLoc && SwitchLoc) {
      if (!fileNameMatches(SwitchLoc->first, TargetLoc->first))
        continue;
      if (SwitchLoc->second > TargetLoc->second)
        continue;
      unsigned Dist = TargetLoc->second - SwitchLoc->second;
      if (!Best || Dist < BestDistance) {
        Best = SI;
        BestDistance = Dist;
      }
      continue;
    }

    if (!Best)
      Best = SI;
  }

  if (Best)
    return Best;

  return nullptr;
}

static const Instruction *findBranchOrSwitchInBB(const BasicBlock *BB) {
  if (!BB) return nullptr;
  if (const Instruction *T = BB->getTerminator())
    if (isBranchOrSwitch(T)) return T;

  for (const Instruction &I : *BB)
    if (isBranchOrSwitch(&I)) return &I;

  return nullptr;
}

static const Instruction *searchSuccessorsForBranch(const BasicBlock *Start,
                                                    unsigned Steps) {
  if (!Start) return nullptr;

  DenseSet<const BasicBlock*> Seen;
  SmallVector<const BasicBlock*, 32> Frontier;
  Frontier.push_back(Start);
  Seen.insert(Start);

  for (unsigned depth = 0; depth <= Steps; ++depth) {
    SmallVector<const BasicBlock*, 32> Next;

    for (const BasicBlock *BB : Frontier) {
      if (const Instruction *Hit = findBranchOrSwitchInBB(BB))
        return Hit;

      if (depth == Steps) continue;
      for (const BasicBlock *Succ : successors(BB)) {
        if (Seen.insert(Succ).second)
          Next.push_back(Succ);
      }
    }

    Frontier.swap(Next);
    if (Frontier.empty()) break;
  }

  return nullptr;
}

// Modified: return matched instructions directly (not just branches)
static SmallVector<const Instruction*, 8>
findTargetInstructions(Module &M, const TargetLoc &T) {
  SmallVector<const Instruction*, 8> Targets;

  for (Function &F : M) {
    if (F.isDeclaration()) continue;

    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (instMatchesTarget(I, T)) {
          Targets.push_back(&I);
        }
      }
    }
  }

  std::set<const Instruction*> U(Targets.begin(), Targets.end());
  Targets.assign(U.begin(), U.end());
  return Targets;
}

// Legacy: search for branches only (for backward compatibility)
static SmallVector<const Instruction*, 8>
findTargetBranches(Module &M, const TargetLoc &T) {
  DenseMap<const Function*, const Instruction*> BestPerFunction;

  for (Function &F : M) {
    if (F.isDeclaration()) continue;

    for (BasicBlock &BB : F) {
      bool HitInThisBB = false;
      const Instruction *DirectBranchHit = nullptr;

      for (Instruction &I : BB) {
        if (instMatchesTarget(I, T)) {
          HitInThisBB = true;
          if (isBranchOrSwitch(&I) && !DirectBranchHit)
            DirectBranchHit = &I;
        }
      }
      if (!HitInThisBB) continue;

      const Instruction *Candidate = nullptr;
      if (DirectBranchHit) {
        Candidate = DirectBranchHit;
      } else if (const Instruction *T0 = findBranchOrSwitchInBB(&BB)) {
        Candidate = T0;
      } else if (const Instruction *Near = searchSuccessorsForBranch(&BB, SearchSuccSteps)) {
        Candidate = Near;
      }

      if (!Candidate)
        continue;

      const Instruction *&Best = BestPerFunction[&F];
      if (!Best) {
        Best = Candidate;
        continue;
      }

      auto lineDistance = [&](const Instruction *I) -> unsigned {
        if (auto Loc = getPrimaryFileLine(*I)) {
          if (fileNameMatches(Loc->first, T.File))
            return (Loc->second > T.Line) ? (Loc->second - T.Line) : (T.Line - Loc->second);
        }
        return std::numeric_limits<unsigned>::max();
      };

      unsigned BestDist = lineDistance(Best);
      unsigned CandDist = lineDistance(Candidate);
      if (CandDist < BestDist)
        Best = Candidate;
    }
  }

  SmallVector<const Instruction*, 8> Targets;
  for (auto &KV : BestPerFunction)
    Targets.push_back(KV.second);

  std::set<const Instruction*> U(Targets.begin(), Targets.end());
  Targets.assign(U.begin(), U.end());
  return Targets;
}

/* ===================== control dependence ===================== */

using CtrlSet = SmallPtrSet<const Instruction*, 8>; // smallsize <= 32
using CtrlDepMap = DenseMap<const BasicBlock*, CtrlSet>;

static CtrlDepMap buildControlDependence(Function &F) {
  CtrlDepMap Map;
  PostDominatorTree PDT;
  PDT.recalculate(F);

  for (BasicBlock &B : F) {
    Instruction *Term = B.getTerminator();
    if (!Term) continue;
    unsigned NSucc = Term->getNumSuccessors();
    if (NSucc < 2) continue;

    auto *BNode = PDT.getNode(&B);
    if (!BNode) continue;
    auto *IDomNode = BNode->getIDom();
    if (!IDomNode) continue;
    const BasicBlock *IPDomB = IDomNode->getBlock();
    if (!IPDomB) continue;

    for (unsigned i = 0; i < NSucc; ++i) {
      const BasicBlock *S = Term->getSuccessor(i);
      const BasicBlock *X = S;
      while (X && X != IPDomB) {
        Map[X].insert(Term);

        auto *XNode = PDT.getNode(const_cast<BasicBlock*>(X));
        if (!XNode) break;
        auto *XIDom = XNode->getIDom();
        if (!XIDom) break;
        X = XIDom->getBlock();
      }
    }
  }

  return Map;
}

// Extend slice to fixed point: add controllers + slice their conditions.
static void extendSliceWithControlDep(SliceResult &SR,
                                      DenseSet<const Value*> &SeenValues,
                                      const CtrlDepMap &CDM,
                                      unsigned MaxRounds,
                                      DenseMap<const Function *, std::unique_ptr<FunctionMemoryAnalysisContext>> &MemCtxCache) {
  if (MaxRounds == 0)
    return;

  bool Changed = true;
  unsigned Round = 0;
  while (Changed && Round < MaxRounds) {
    Changed = false;
    ++Round;

    SmallVector<const Instruction*, 256> Snapshot = SR.Insts;

    for (const Instruction *I : Snapshot) {
      const BasicBlock *BB = I->getParent();
      if (!BB) continue;

      auto It = CDM.find(BB);
      if (It == CDM.end()) continue;

      for (const Instruction *CtrlTerm : It->second) {
        if (!SR.InstSet.count(CtrlTerm)) {
          addInst(SR, CtrlTerm);
          Changed = true;
        }

        if (auto *BI = dyn_cast<BranchInst>(CtrlTerm)) {
          if (BI->isConditional())
            backwardSliceValue(BI->getCondition(), SR, SeenValues, MemCtxCache);
        } else if (auto *SI = dyn_cast<SwitchInst>(CtrlTerm)) {
          backwardSliceValue(SI->getCondition(), SR, SeenValues, MemCtxCache);
        }
      }
    }
  }
}

/* ===================== source extraction (with function names) ===================== */

static std::vector<std::string> readAllLines(const std::string &Path) {
  std::vector<std::string> Lines;
  std::ifstream in(Path);
  if (!in.good()) return Lines;
  std::string s;
  while (std::getline(in, s)) Lines.push_back(s);
  return Lines;
}

static std::string trimCopy(StringRef S) {
  return S.trim().str();
}

static bool shouldNegateAssert() {
  if (StringRef(BranchCoverage).equals_lower("true"))
    return true;
  if (StringRef(BranchCoverage).equals_lower("false"))
    return false;
  return AssertNegate;
}

static std::optional<std::pair<unsigned, std::string>>
findEnclosingCaseLabel(const std::vector<std::string> &Lines,
                       unsigned TargetLine,
                       unsigned SwitchLine = 0) {
  if (Lines.empty() || TargetLine == 0)
    return std::nullopt;

  unsigned StartLine = std::min<unsigned>(TargetLine, Lines.size());
  unsigned LowerBound = (SwitchLine > 0 && SwitchLine <= StartLine) ? SwitchLine : 1;
  for (unsigned Line = StartLine; Line >= LowerBound; --Line) {
    StringRef Text = StringRef(Lines[Line - 1]).trim();
    if (Text.startswith("case ")) {
      size_t ColonPos = Text.find(':');
      if (ColonPos != StringRef::npos) {
        StringRef Value = Text.drop_front(strlen("case ")).take_front(ColonPos - strlen("case "));
        return std::make_pair(Line, trimCopy(Value));
      }
    }
    if (Text.startswith("default:"))
      return std::make_pair(Line, std::string("default"));
    if (Line == LowerBound)
      break;
  }

  return std::nullopt;
}

// file -> (line -> set<function>)
using FileLineFuncMap = std::map<std::string, std::map<unsigned, std::set<std::string>>>;

// ============== v2 新增：函数边界检测 ==============
struct FuncBoundary {
  std::string Name;
  unsigned StartLine;  // 函数签名开始行
  unsigned BodyStart;  // 函数体开始行（通常是 "{"）
  unsigned BodyEnd;    // 函数体结束行（通常是 "}"）
};

// 检测函数边界：通过扫描源代码找到函数签名和边界
static std::vector<FuncBoundary> detectFunctionBoundaries(const std::vector<std::string> &Lines) {
  std::vector<FuncBoundary> Bounds;
  std::string currentFunc;
  int braceDepth = 0;
  unsigned funcStartLine = 0;
  unsigned bodyStartLine = 0;
  bool inFunc = false;
  bool sigFound = false;

  for (unsigned i = 0; i < Lines.size(); ++i) {
    const std::string &line = Lines[i];
    std::string trimmed = line;
    // 简单去除前导空格
    size_t start = trimmed.find_first_not_of(" \t");
    if (start != std::string::npos)
      trimmed = trimmed.substr(start);
    else
      trimmed = "";

    // 检测函数签名（简化启发式）
    // 匹配模式: type funcname( 或 type funcname (
    if (!inFunc && !trimmed.empty() && trimmed[0] != '#' && trimmed[0] != '/' &&
        trimmed.find("/*") == std::string::npos) {
      // 查找函数名模式：包含 ( 且不以 ; 结尾
      size_t parenPos = trimmed.find('(');
      if (parenPos != std::string::npos) {
        // 检查是否是函数定义（而非声明）
        // 简单启发式：如果这一行或接下来几行有 {，则认为是函数定义
        bool hasBrace = trimmed.find('{') != std::string::npos;
        if (!hasBrace) {
          for (unsigned j = i + 1; j < std::min(i + 5u, (unsigned)Lines.size()); ++j) {
            if (Lines[j].find('{') != std::string::npos) {
              hasBrace = true;
              break;
            }
            // 如果遇到 ; 说明是声明而非定义
            if (Lines[j].find(';') != std::string::npos)
              break;
          }
        }
        if (hasBrace) {
          // 提取函数名
          size_t nameEnd = parenPos;
          // 向前找函数名
          while (nameEnd > 0 && (isspace(trimmed[nameEnd-1]) || trimmed[nameEnd-1] == '*'))
            nameEnd--;
          size_t nameStart = nameEnd;
          while (nameStart > 0 && (isalnum(trimmed[nameStart-1]) || trimmed[nameStart-1] == '_'))
            nameStart--;
          if (nameStart < nameEnd) {
            currentFunc = trimmed.substr(nameStart, nameEnd - nameStart);
            funcStartLine = i + 1;  // 1-indexed
            inFunc = true;
            sigFound = true;
          }
        }
      }
    }

    // 追踪大括号深度
    for (char c : trimmed) {
      if (c == '{') {
        if (inFunc && braceDepth == 0) {
          bodyStartLine = i + 1;  // 1-indexed
        }
        braceDepth++;
      } else if (c == '}') {
        braceDepth--;
        if (inFunc && braceDepth == 0) {
          FuncBoundary fb;
          fb.Name = currentFunc;
          fb.StartLine = funcStartLine;
          fb.BodyStart = bodyStartLine;
          fb.BodyEnd = i + 1;  // 1-indexed
          Bounds.push_back(fb);
          inFunc = false;
          sigFound = false;
          currentFunc.clear();
        }
      }
    }
  }

  return Bounds;
}

// 检查某行是否在函数边界内
static const FuncBoundary* findContainingFunc(const std::vector<FuncBoundary> &Bounds, unsigned Line) {
  for (const auto &fb : Bounds) {
    if (Line >= fb.StartLine && Line <= fb.BodyEnd)
      return &fb;
  }
  return nullptr;
}

// ============== v2 改进：新的输出函数 ==============
static void printSourceSliceFromMap(raw_ostream &OS,
                                    const FileLineFuncMap &FileLineFuncs,
                                    const TargetBranchMap &TargetBranches,
                                    unsigned Context,
                                    const std::vector<OrderedFunctionView> *PreferredOrder = nullptr) {
  if (V2Config::CodeBlockFormat) {
    OS << "=== Source Slice ===\n";

    struct FileRenderData {
      std::vector<std::string> SrcLines;
      std::vector<FuncBoundary> FuncBounds;
      std::set<unsigned> Want;
      std::set<unsigned> TargetLines;
    };

    std::map<std::string, FileRenderData> RenderData;
    for (const auto &kv : FileLineFuncs) {
      const std::string &File = kv.first;
      const std::map<unsigned, std::set<std::string>> &LineToFuncs = kv.second;

      auto SrcLines = readAllLines(File);
      if (SrcLines.empty()) {
        OS << "[WARN] cannot open source file: " << File << "\n";
        continue;
      }

      FileRenderData Data;
      Data.SrcLines = std::move(SrcLines);
      if (V2Config::KeepFuncBoundary)
        Data.FuncBounds = detectFunctionBoundaries(Data.SrcLines);

      for (const auto &lf : LineToFuncs) {
        unsigned L = lf.first;
        if (L == 0) continue;
        Data.TargetLines.insert(L);

        unsigned Start = (L > Context) ? (L - Context) : 1;
        unsigned End = std::min<unsigned>(L + Context, (unsigned)Data.SrcLines.size());
        for (unsigned X = Start; X <= End; ++X)
          Data.Want.insert(X);
      }

      if (V2Config::KeepFuncBoundary) {
        std::set<std::string> IncludedFuncs;
        for (unsigned L : Data.Want) {
          const FuncBoundary *FB = findContainingFunc(Data.FuncBounds, L);
          if (FB && IncludedFuncs.insert(FB->Name).second) {
            for (unsigned X = FB->StartLine; X <= FB->BodyStart; ++X)
              Data.Want.insert(X);
            Data.Want.insert(FB->BodyEnd);
          }
        }
      }

      RenderData.emplace(File, std::move(Data));
    }

    std::set<std::pair<std::string, unsigned>> Printed;
    std::set<std::pair<std::string, unsigned>> AssertPrinted;
    std::string CurrentFile;
    unsigned PrevLine = 0;

    auto printFileHeaderIfNeeded = [&](const std::string &File) {
      if (CurrentFile == File)
        return;
      CurrentFile = File;
      PrevLine = 0;
      std::string BaseName = File;
      size_t LastSlash = BaseName.find_last_of("/\\");
      if (LastSlash != std::string::npos)
        BaseName = BaseName.substr(LastSlash + 1);
      OS << "\n/* FILE: " << BaseName << " */\n";
    };

    auto printAssertReplacementIfNeeded = [&](const std::string &File, unsigned L) -> bool {
      auto Key = std::make_pair(File, L);
      if (AssertPrinted.count(Key))
        return false;
      auto TargetIt = TargetBranches.find(File);
      if (!InsertAssert || TargetIt == TargetBranches.end())
        return false;
      auto LineIt = TargetIt->second.find(L);
      if (LineIt == TargetIt->second.end())
        return false;

      const TargetBranchInfo &TB = LineIt->second;
      const bool Negate = shouldNegateAssert();
      if (TB.IsBranch && !TB.Condition.empty()) {
        std::string AssertStmt = AssertPrefix;
        if (Negate)
          AssertStmt += "(!(" + TB.Condition + "));";
        else
          AssertStmt += "(" + TB.Condition + ");";
        OS << ">>> " << AssertStmt << "\n";
      } else if (TB.IsSwitch && !TB.Condition.empty()) {
        std::string AssertStmt = AssertPrefix;
        std::string CaseExpr = TB.CaseValue.empty() ? "<case_value>" : TB.CaseValue;
        if (Negate)
          AssertStmt += "(!(" + TB.Condition + " == " + CaseExpr + "));";
        else
          AssertStmt += "(" + TB.Condition + " == " + CaseExpr + ");";
        OS << ">>> " << AssertStmt << "\n";
      } else {
        return false;
      }
      AssertPrinted.insert(Key);
      return true;
    };

    auto printLine = [&](const std::string &File, unsigned L, FileRenderData &Data) {
      if (!(L >= 1 && L <= Data.SrcLines.size()))
        return;
      auto Key = std::make_pair(File, L);
      if (!Printed.insert(Key).second)
        return;

      if (CurrentFile == File && PrevLine != 0 && L <= PrevLine) {
        CurrentFile.clear();
        PrevLine = 0;
      }

      printFileHeaderIfNeeded(File);

      if (V2Config::GapThreshold > 0 && PrevLine > 0) {
        unsigned Gap = L - PrevLine - 1;
        if (Gap >= V2Config::GapThreshold)
          OS << "    /* ... " << Gap << " lines omitted ... */\n";
      }

      if (printAssertReplacementIfNeeded(File, L)) {
        PrevLine = L;
        return;
      }
      OS << (Data.TargetLines.count(L) ? ">>> " : "    ");
      OS << Data.SrcLines[L - 1] << "\n";
      PrevLine = L;
    };

    if (PreferredOrder && !PreferredOrder->empty()) {
      for (const OrderedFunctionView &View : *PreferredOrder) {
        auto DataIt = RenderData.find(View.File);
        if (DataIt == RenderData.end())
          continue;
        FileRenderData &Data = DataIt->second;
        const FuncBoundary *FB = findContainingFunc(Data.FuncBounds, View.Line);
        if (!FB)
          continue;

        for (unsigned L : Data.Want) {
          if (L >= FB->StartLine && L <= FB->BodyEnd)
            printLine(View.File, L, Data);
        }
      }
    } else {
      for (auto &KV : RenderData) {
        const std::string &File = KV.first;
        FileRenderData &Data = KV.second;
        for (unsigned L : Data.Want)
          printLine(File, L, Data);
      }
    }

    OS << "\n=== End Source Slice ===\n";
  } else {
    OS << "=== Source Slice ===\n";

    for (const auto &kv : FileLineFuncs) {
      const std::string &File = kv.first;
      const std::map<unsigned, std::set<std::string>> &LineToFuncs = kv.second;

      auto SrcLines = readAllLines(File);
      if (SrcLines.empty()) {
        OS << "[WARN] cannot open source file: " << File << "\n";
        continue;
      }

      std::set<unsigned> Want;
      for (const auto &lf : LineToFuncs) {
        unsigned L = lf.first;
        if (L == 0) continue;
        unsigned start = (L > Context) ? (L - Context) : 1;
        unsigned end = std::min<unsigned>(L + Context, (unsigned)SrcLines.size());
        for (unsigned x = start; x <= end; ++x)
          Want.insert(x);
      }

      OS << "\n-- " << File << " --\n";

      // 改进1: 在原始格式中也添加 Gap 标记
      unsigned prevLine = 0;
      for (unsigned L : Want) {
        if (!(L >= 1 && L <= SrcLines.size())) continue;

        // Gap 标记
        if (V2Config::GapThreshold > 0 && prevLine > 0) {
          unsigned gap = L - prevLine - 1;
          if (gap >= V2Config::GapThreshold) {
            OS << "        /* ... " << gap << " lines omitted ... */\n";
          }
        }

        OS << File << ":" << L;

        auto It = LineToFuncs.find(L);
        if (It != LineToFuncs.end() && !It->second.empty()) {
          OS << " [func=";
          bool first = true;
          for (const auto &Fn : It->second) {
            if (!first) OS << ",";
            OS << Fn;
            first = false;
          }
          OS << "]";
        }

        OS << ": " << SrcLines[L - 1] << "\n";
        prevLine = L;
      }
    }

    OS << "\n=== End Source Slice ===\n";
  }
}

class SVFCallPathAnalyzer {
public:
  SVFCallPathAnalyzer() = default;

  ~SVFCallPathAnalyzer() {
    // SVF relies on several process-wide singletons. In practice, eagerly
    // tearing them down here is unstable for our standalone/plugin execution
    // mode and can crash after all results have already been produced.
    // Let the process reclaim them on exit instead.
  }

  bool initialize(Module &M, raw_ostream &Log) {
    if (Built)
      return Ready;

    Built = true;
    SVF::LLVMModuleSet *ModuleSet = SVF::LLVMModuleSet::getLLVMModuleSet();
    if (!ModuleSet) {
      InitError = "failed to create LLVMModuleSet";
      return false;
    }

    SVF::SVFModule *SVFModule = ModuleSet->buildSVFModule(M);
    if (!SVFModule) {
      InitError = "failed to build SVF module";
      return false;
    }

    SVF::PAGBuilder Builder;
    PAG = Builder.build(SVFModule);
    if (!PAG) {
      InitError = "failed to build SVF PAG";
      return false;
    }

    PTA = SVF::AndersenWaveDiff::createAndersenWaveDiff(PAG);
    if (!PTA) {
      InitError = "failed to build SVF Andersen analysis";
      return false;
    }

    CallGraph = PTA->getPTACallGraph();
    if (!CallGraph) {
      InitError = "failed to obtain SVF PTA call graph";
      return false;
    }

    Ready = true;
    Log << "[branch-cond-slice] SVF call-path analysis ready\n";
    return true;
  }

  CallPathResult findEntryToTargetPath(Module &M, const Function *Target,
                                       raw_ostream &Log) {
    CallPathResult Result;
    Result.EntryName = SliceEntryFunction;

    if (!Target) {
      Result.Error = "null target function";
      return Result;
    }

    if (!initialize(M, Log)) {
      Result.Error = InitError;
      return Result;
    }

    Result.Available = true;

    const Function *EntryLLVM = M.getFunction(SliceEntryFunction);
    const SVF::SVFFunction *Entry = nullptr;
    if (EntryLLVM && !EntryLLVM->isDeclaration()) {
      Entry = SVF::LLVMModuleSet::getLLVMModuleSet()->getSVFFunction(EntryLLVM);
    } else {
      Entry = SVF::SVFUtil::getFunction(SliceEntryFunction);
      if (Entry)
        EntryLLVM = Entry->getLLVMFun();
    }

    if (!Entry || !EntryLLVM) {
      Result.Error = "entry function not found: " + SliceEntryFunction;
      return Result;
    }

    const SVF::SVFFunction *TargetSVF =
        SVF::LLVMModuleSet::getLLVMModuleSet()->getSVFFunction(Target);
    if (!TargetSVF) {
      Result.Error = "target function is not available in SVF";
      return Result;
    }

    const auto *EntryNode = CallGraph->getCallGraphNode(Entry);
    const auto *TargetNode = CallGraph->getCallGraphNode(TargetSVF);
    if (!EntryNode || !TargetNode) {
      Result.Error = "failed to map entry or target into SVF call graph";
      return Result;
    }

    DenseSet<const SVF::PTACallGraphNode*> Visited;
    DenseMap<const SVF::PTACallGraphNode*, const SVF::PTACallGraphNode*> PrevNode;
    DenseMap<const SVF::PTACallGraphNode*, const SVF::PTACallGraphEdge*> PrevEdge;
    SmallVector<const SVF::PTACallGraphNode*, 32> Queue;
    Queue.push_back(EntryNode);
    Visited.insert(EntryNode);

    size_t Index = 0;
    while (Index < Queue.size()) {
      const SVF::PTACallGraphNode *Node = Queue[Index++];
      if (Node == TargetNode)
        break;

      for (auto It = Node->OutEdgeBegin(), Eit = Node->OutEdgeEnd(); It != Eit; ++It) {
        const SVF::PTACallGraphEdge *Edge = *It;
        const SVF::PTACallGraphNode *Succ = Edge->getDstNode();
        if (!Visited.insert(Succ).second)
          continue;
        PrevNode[Succ] = Node;
        PrevEdge[Succ] = Edge;
        Queue.push_back(Succ);
      }
    }

    if (!Visited.count(TargetNode)) {
      Result.Error = "target is not reachable from entry in SVF call graph";
      return Result;
    }

    SmallVector<CallPathStep, 16> ReverseSteps;
    const SVF::PTACallGraphNode *Current = TargetNode;
    while (Current != EntryNode) {
      auto EdgeIt = PrevEdge.find(Current);
      auto NodeIt = PrevNode.find(Current);
      if (EdgeIt == PrevEdge.end() || NodeIt == PrevNode.end())
        break;

      const SVF::PTACallGraphEdge *Edge = EdgeIt->second;
      const SVF::PTACallGraphNode *Pred = NodeIt->second;

      const SVF::CallBlockNode *CallBlock = nullptr;
      bool IsIndirect = false;
      if (!Edge->getDirectCalls().empty()) {
        CallBlock = *Edge->getDirectCalls().begin();
      } else if (!Edge->getIndirectCalls().empty()) {
        CallBlock = *Edge->getIndirectCalls().begin();
        IsIndirect = true;
      }

      CallPathStep Step;
      Step.Caller = Pred->getFunction() ? Pred->getFunction()->getLLVMFun() : nullptr;
      Step.Callee = Current->getFunction() ? Current->getFunction()->getLLVMFun() : nullptr;
      Step.CallSite = CallBlock ? CallBlock->getCallSite() : nullptr;
      Step.IsIndirect = IsIndirect;
      ReverseSteps.push_back(Step);

      Current = Pred;
    }

    Result.Reached = true;
    Result.Steps.assign(ReverseSteps.rbegin(), ReverseSteps.rend());
    return Result;
  }

private:
  bool Built = false;
  bool Ready = false;
  std::string InitError;
  SVF::PAG *PAG = nullptr;
  SVF::AndersenWaveDiff *PTA = nullptr;
  SVF::PTACallGraph *CallGraph = nullptr;
};

static void printCallPath(raw_ostream &OS, const CallPathResult &Path,
                          const Function &Target) {
  OS << "\n=== SVF Entry Path ===\n";
  if (!Path.Available) {
    OS << "SVF unavailable: " << Path.Error << "\n";
    OS << "=== End SVF Entry Path ===\n";
    return;
  }
  if (!Path.Reached) {
    OS << "No path from entry `" << Path.EntryName << "` to target function `"
       << Target.getName() << "`: " << Path.Error << "\n";
    OS << "=== End SVF Entry Path ===\n";
    return;
  }

  OS << "entry: " << Path.EntryName << "\n";
  if (Path.Steps.empty()) {
    OS << "target function is the entry itself: " << Target.getName() << "\n";
    OS << "=== End SVF Entry Path ===\n";
    return;
  }

  unsigned Index = 1;
  for (const CallPathStep &Step : Path.Steps) {
    OS << Index++ << ". ";
    OS << (Step.Caller ? Step.Caller->getName() : "<unknown-caller>");
    OS << " -> ";
    OS << (Step.Callee ? Step.Callee->getName() : "<unknown-callee>");
    OS << (Step.IsIndirect ? " [indirect]" : " [direct]");
    if (Step.CallSite) {
      if (auto Loc = getPrimaryFileLine(*Step.CallSite))
        OS << " @ " << Loc->first << ":" << Loc->second;
    }
    OS << "\n";
  }
  OS << "=== End SVF Entry Path ===\n";
}

static void mergeCallPathIntoSourceMap(const CallPathResult &Path,
                                       FileLineFuncMap &GlobalFileLineFuncs) {
  if (!Path.Available || !Path.Reached)
    return;

  for (const CallPathStep &Step : Path.Steps) {
    if (Step.Caller) {
      if (auto Loc = getFunctionSourceLoc(*Step.Caller))
        GlobalFileLineFuncs[Loc->File][Loc->Line].insert("<entry-path-func>");
    }
    if (Step.Callee) {
      if (auto Loc = getFunctionSourceLoc(*Step.Callee))
        GlobalFileLineFuncs[Loc->File][Loc->Line].insert("<entry-path-func>");
    }
    if (Step.CallSite) {
      if (auto Loc = getPrimaryFileLine(*Step.CallSite))
        GlobalFileLineFuncs[Loc->first][Loc->second].insert("<entry-path-call>");
    }
  }
}

static SmallVector<const Instruction*, 8>
selectTargetsForKind(Module &M, const TargetLoc &T, TargetKind Kind) {
  switch (Kind) {
  case TargetKind::Branch:
    return findTargetBranches(M, T);
  case TargetKind::Stmt:
    return findTargetInstructions(M, T);
  case TargetKind::SwitchCase: {
    SmallVector<const Instruction*, 8> Targets;
    auto Switches = findAllSwitches(M);
    if (const SwitchInst *ContainingSwitch = findSwitchContainingLine(Switches, T))
      Targets.push_back(ContainingSwitch);
    return Targets;
  }
  case TargetKind::Auto:
  default:
    return findTargetInstructions(M, T);
  }
}

static void appendOrderedFunction(const Function *F,
                                  std::vector<OrderedFunctionView> &Order,
                                  std::set<std::pair<std::string, unsigned>> &Seen) {
  if (!F)
    return;
  auto Loc = getFunctionSourceLoc(*F);
  if (!Loc)
    return;
  auto Key = std::make_pair(Loc->File, Loc->Line);
  if (!Seen.insert(Key).second)
    return;
  Order.push_back({Loc->File, Loc->Line, F->getName().str()});
}

static std::unique_ptr<Module> loadModule(LLVMContext &Context,
                                          const std::string &Path) {
  SMDiagnostic Err;
  auto ModuleOrErr = parseIRFile(Path, Err, Context);
  if (ModuleOrErr)
    return ModuleOrErr;

  auto BufferOrErr = MemoryBuffer::getFile(Path);
  if (!BufferOrErr) {
    errs() << "failed to read input: " << Path << "\n";
    return nullptr;
  }

  auto BitcodeOrErr =
      parseBitcodeFile(BufferOrErr.get()->getMemBufferRef(), Context);
  if (!BitcodeOrErr) {
    errs() << "failed to parse bitcode: " << Path << "\n";
    logAllUnhandledErrors(BitcodeOrErr.takeError(), errs(),
                          "bitcode parse failed: ");
    return nullptr;
  }
  return std::move(*BitcodeOrErr);
}

/* ===================== main pass ===================== */

struct BranchCondSlicePass : public PassInfoMixin<BranchCondSlicePass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    raw_ostream &CmdOS = errs();

    auto TL = parseLoc(SliceLoc);
    if (!TL) {
      CmdOS << "[branch-cond-slice] ERROR: -slice-loc must be file:line\n";
      return PreservedAnalyses::all();
    }
    auto OriginalCaseTL = parseLoc(SliceCaseLoc);
    if (OriginalCaseTL && !fileNameMatches(OriginalCaseTL->File, TL->File))
      OriginalCaseTL.reset();

    const TargetKind Kind = parseTargetKind(SliceTargetKind);
    auto Targets = selectTargetsForKind(M, *TL, Kind);

    // Prepare Source Slice output stream (file if provided, else cmd)
    // Do this early so we can write error messages to the file when no targets found
    std::unique_ptr<raw_fd_ostream> SrcFileOS;
    raw_ostream *SrcOS = &CmdOS;

    if (PrintSourceSlice && !SourceOut.empty()) {
      std::error_code EC;
      SrcFileOS = std::make_unique<raw_fd_ostream>(SourceOut, EC);
      if (EC) {
        CmdOS << "[branch-cond-slice] WARN: cannot open -slice-out file: "
              << SourceOut << " (" << EC.message() << ")\n";
        CmdOS << "  -> fallback: print Source Slice to cmd\n";
        SrcFileOS.reset();
      } else {
        SrcOS = SrcFileOS.get();
        CmdOS << "[branch-cond-slice] Source Slice will be written to: " << SourceOut << "\n";
      }
    }

    if (Targets.empty()) {
      CmdOS << "[branch-cond-slice] No matching instruction found for "
            << TL->File << ":" << TL->Line << "\n";
      CmdOS << "  Trying to find a switch statement containing this line...\n";

      // Try to find a switch statement that contains this line (for case labels)
      auto Switches = findAllSwitches(M);
      const SwitchInst *ContainingSwitch = findSwitchContainingLine(Switches, *TL);

      if (ContainingSwitch) {
        CmdOS << "  [found] Switch at ";
        if (auto Loc = getPrimaryFileLine(*ContainingSwitch)) {
          CmdOS << Loc->first << ":" << Loc->second;
        }
        CmdOS << " - slicing switch condition\n";

        // Create a synthetic target from the switch instruction
        Targets.push_back(ContainingSwitch);
      } else {
        CmdOS << "  Hints: compile with -g, try -O0/-Og, or the code may be in a conditional compilation block\n";

        // Write error message to the output file if specified
        if (PrintSourceSlice && SrcOS != &CmdOS) {
          *SrcOS << "=== Source Slice ===\n\n";
          *SrcOS << "ERROR: No matching instruction found for "
                 << TL->File << ":" << TL->Line << "\n\n";
          *SrcOS << "=== End Source Slice ===\n";
          SrcOS->flush();
        }

        return PreservedAnalyses::all();
      }
    }

    CmdOS << "[branch-cond-slice] Matched " << Targets.size()
          << " target(s) for " << TL->File << ":" << TL->Line << "\n";

    // Global: file -> line -> {functions}
    FileLineFuncMap GlobalFileLineFuncs;

    // v2 新增：目标分支信息（用于插入 assert）
    TargetBranchMap GlobalTargetBranches;

    SVFCallPathAnalyzer CallPathAnalyzer;
    std::map<const Function*, CallPathResult> CallPathCache;
    std::vector<OrderedFunctionView> PreferredFunctionOrder;
    std::set<std::pair<std::string, unsigned>> PreferredFunctionSeen;
    DenseMap<const Function *, std::unique_ptr<FunctionMemoryAnalysisContext>>
        MemCtxCache;

    // Combined slice result for all targets (used for type definition collection)
    SliceResult CombinedSR;

    unsigned PrintedIR = 0;

    for (const Instruction *Target : Targets) {
      const Function *F = Target->getFunction();
      if (!F) continue;

      CmdOS << "\n== Target in function: " << F->getName() << " ==\n";
      printInstWithLoc(CmdOS, Target);

      if (UseSVFCallPath) {
        auto CacheIt = CallPathCache.find(F);
        if (CacheIt == CallPathCache.end()) {
          CallPathResult Path = CallPathAnalyzer.findEntryToTargetPath(M, F, CmdOS);
          printCallPath(CmdOS, Path, *F);
          if (MergeSVFCallPathIntoSource)
            mergeCallPathIntoSourceMap(Path, GlobalFileLineFuncs);
          if (Path.Available && Path.Reached) {
            for (const CallPathStep &Step : Path.Steps)
              appendOrderedFunction(Step.Caller, PreferredFunctionOrder,
                                    PreferredFunctionSeen);
          }
          appendOrderedFunction(F, PreferredFunctionOrder, PreferredFunctionSeen);
          CacheIt = CallPathCache.emplace(F, std::move(Path)).first;
        } else {
          if (MergeSVFCallPathIntoSource)
            mergeCallPathIntoSourceMap(CacheIt->second, GlobalFileLineFuncs);
          if (CacheIt->second.Available && CacheIt->second.Reached) {
            for (const CallPathStep &Step : CacheIt->second.Steps)
              appendOrderedFunction(Step.Caller, PreferredFunctionOrder,
                                    PreferredFunctionSeen);
          }
          appendOrderedFunction(F, PreferredFunctionOrder, PreferredFunctionSeen);
        }
      }

      // Check if target is in a switch case block (before checking branch type)
      const SwitchInst *ParentSwitch = findParentSwitchForCase(Target);

      // Check if target is a branch/switch
      bool isBranch = isBranchOrSwitch(Target);

      const Value *CondV = nullptr;
      if (auto *BI = dyn_cast<BranchInst>(Target)) {
        if (!BI->isConditional()) {
          // Before skipping, check if this unconditional branch is in a switch case block
          if (ParentSwitch) {
            // This unconditional branch is in a case block - slice the switch condition
            CondV = ParentSwitch->getCondition();
            CmdOS << "  [case-block] unconditional branch, found parent switch at ";
            if (auto Loc = getPrimaryFileLine(*ParentSwitch)) {
              CmdOS << Loc->first << ":" << Loc->second << " ";
            }
            CmdOS << "[switch-cond] " << *CondV << "\n";
            isBranch = true; // Treat as branch for slicing logic
          } else {
            CmdOS << "  (unconditional branch; skip)\n";
            continue;
          }
        } else {
          CondV = BI->getCondition();
          CmdOS << "  [branch-cond] " << *CondV << "\n";
        }
      } else if (auto *SI = dyn_cast<SwitchInst>(Target)) {
        CondV = SI->getCondition();
        CmdOS << "  [switch-cond] " << *CondV << "\n";
      } else if (ParentSwitch) {
        // Target is in a switch case block - slice the switch condition
        CondV = ParentSwitch->getCondition();
        CmdOS << "  [case-block] found parent switch at ";
        if (auto Loc = getPrimaryFileLine(*ParentSwitch)) {
          CmdOS << Loc->first << ":" << Loc->second << " ";
        }
        CmdOS << "[switch-cond] " << *CondV << "\n";
        isBranch = true; // Treat as branch for slicing logic
      } else {
        CmdOS << "  [non-branch instruction] - slicing all operands\n";
      }

      SliceResult SR;
      DenseSet<const Value*> SeenValues;

      if (isBranch && CondV) {
        // Branch/switch: slice only the condition
        backwardSliceValue(CondV, SR, SeenValues, MemCtxCache);
      } else {
        // Non-branch: slice all operands of the instruction (including function args)
        CmdOS << "  [operands] ";
        bool firstOp = true;
        for (const Use &U : Target->operands()) {
          const Value *Op = U.get();
          if (!firstOp) CmdOS << ", ";
          CmdOS << *Op;
          firstOp = false;
          backwardSliceValue(Op, SR, SeenValues, MemCtxCache);
        }
        CmdOS << "\n";
      }

      if (IncludeControlDep) {
        Function &FF = *const_cast<Function*>(F);
        CtrlDepMap CDM = buildControlDependence(FF);
        extendSliceWithControlDep(SR, SeenValues, CDM, ControlDepDepth,
                                  MemCtxCache);
      }

      CmdOS << "  [slice] IR instructions: " << SR.Insts.size()
            << (IncludeControlDep ? " (with control dep)" : "") << "\n";

      // v2 新增：收集目标分支信息（用于插入 assert）
      if (InsertAssert && isBranch && CondV) {
        // 获取目标位置信息
        const Instruction *AssertInst =
            (ParentSwitch && !isa<SwitchInst>(Target)) ? cast<Instruction>(ParentSwitch)
                                                       : Target;
        if (auto Loc = getPrimaryFileLine(*AssertInst)) {
          TargetBranchInfo TBInfo;
          TBInfo.File = Loc->first;
          TBInfo.Line = Loc->second;
          TBInfo.IsBranch = isa<BranchInst>(Target) && ParentSwitch == nullptr;
          TBInfo.IsSwitch = isa<SwitchInst>(AssertInst) || (ParentSwitch != nullptr);

          // 尝试从源码提取条件表达式
          auto SrcLines = readAllLines(TBInfo.File);
          if (Loc->second >= 1 && Loc->second <= SrcLines.size()) {
            std::string srcLine = SrcLines[Loc->second - 1];
            // 简单提取 if/switch 后的条件
            // 查找 if( 或 switch( 模式
            size_t ifPos = srcLine.find("if");
            size_t switchPos = srcLine.find("switch");
            size_t parenPos = srcLine.find('(');

            if (ifPos != std::string::npos && parenPos != std::string::npos && parenPos > ifPos) {
              // 提取 if 条件
              int depth = 0;
              size_t start = parenPos;
              for (size_t i = parenPos; i < srcLine.size(); ++i) {
                if (srcLine[i] == '(') depth++;
                else if (srcLine[i] == ')') {
                  depth--;
                  if (depth == 0) {
                    TBInfo.Condition = srcLine.substr(start + 1, i - start - 1);
                    break;
                  }
                }
              }
            } else if (switchPos != std::string::npos && parenPos != std::string::npos && parenPos > switchPos) {
              // 提取 switch 条件
              int depth = 0;
              size_t start = parenPos;
              for (size_t i = parenPos; i < srcLine.size(); ++i) {
                if (srcLine[i] == '(') depth++;
                else if (srcLine[i] == ')') {
                  depth--;
                  if (depth == 0) {
                    TBInfo.Condition = srcLine.substr(start + 1, i - start - 1);
                    break;
                  }
                }
              }
            }

            // 如果没有提取到条件，使用 IR 的条件值
            if (TBInfo.Condition.empty()) {
              std::string condStr;
              raw_string_ostream condOS(condStr);
              CondV->print(condOS);
              // 简化 IR 格式
              TBInfo.Condition = "<see IR above>";
            }

            if (TBInfo.IsSwitch) {
              unsigned SearchLine = (OriginalCaseTL && OriginalCaseTL->Line != 0)
                                        ? OriginalCaseTL->Line
                                        : TL->Line;
              unsigned SwitchLine = Loc->second;
              if (auto CaseInfo = findEnclosingCaseLabel(SrcLines, SearchLine, SwitchLine)) {
                TBInfo.CaseLine = CaseInfo->first;
                TBInfo.CaseValue = CaseInfo->second;
              }
            }
          }

          GlobalTargetBranches[TBInfo.File][TBInfo.Line] = TBInfo;
          CmdOS << "  [assert-target] " << TBInfo.File << ":" << TBInfo.Line;
          if (!TBInfo.Condition.empty())
            CmdOS << " condition=\"" << TBInfo.Condition << "\"";
          CmdOS << "\n";
        }
      }

      // Collect source locations for slice instructions, with function name
      if (PrintSourceSlice) {
        for (const Instruction *I : SR.Insts) {
          // Also add to combined slice result for type definition collection
          addInst(CombinedSR, I);

          const Function *IF = I->getFunction();
          std::string FuncName = IF ? IF->getName().str() : std::string("<unknown>");

          SmallVector<std::pair<std::string, unsigned>, 4> Locs;
          collectAllSourceLocations(*I, Locs);
          for (auto &L : Locs) {
            if (!L.first.empty() && L.second != 0)
              GlobalFileLineFuncs[L.first][L.second].insert(FuncName);
          }
        }

        // For case blocks: include both the target case line and the switch line
        if (ParentSwitch) {
          // Add the switch statement location
          if (auto SwitchLoc = getPrimaryFileLine(*ParentSwitch)) {
            GlobalFileLineFuncs[SwitchLoc->first][SwitchLoc->second].insert("<switch>");
            if (fileNameMatches(SwitchLoc->first, TL->File)) {
              unsigned SearchLine = (OriginalCaseTL && OriginalCaseTL->Line != 0)
                                        ? OriginalCaseTL->Line
                                        : TL->Line;
              GlobalFileLineFuncs[SwitchLoc->first][SearchLine].insert("<case-target>");
              auto SrcLines = readAllLines(SwitchLoc->first);
              if (auto CaseInfo = findEnclosingCaseLabel(SrcLines, SearchLine, SwitchLoc->second))
                GlobalFileLineFuncs[SwitchLoc->first][CaseInfo->first].insert("<case-label>");
            }
          }
        } else {
          // For non-case targets: ensure target location line included
          SmallVector<std::pair<std::string, unsigned>, 4> TargetLocs;
          collectAllSourceLocations(*Target, TargetLocs);
          for (auto &L : TargetLocs) {
            if (!L.first.empty() && L.second != 0)
              GlobalFileLineFuncs[L.first][L.second].insert("<target>");
          }
        }
      }

      // Print IR slice to cmd
      if (PrintIRSlice) {
        for (const Instruction *I : SR.Insts) {
          if (MaxIRSliceInsts && PrintedIR >= MaxIRSliceInsts) {
            CmdOS << "  ... (IR slice-print truncated by -slice-max)\n";
            break;
          }
          printInstWithLoc(CmdOS, I);
          ++PrintedIR;
        }
      }
    }

    // Collect struct type definitions from debug info
    // This adds custom struct definitions used in the slice to the output
    if (PrintSourceSlice && IncludeSourceTypeInfo && !CombinedSR.Insts.empty()) {
      DenseSet<const MDNode*> VisitedTypes;
      std::set<std::string> UsedTypeNames;

      // Collect all struct types used in the slice
      for (const Instruction *I : CombinedSR.Insts) {
        Type *InstType = I->getType();
        if (!InstType) continue;

        // Follow pointer types to get the actual struct type
        while (InstType->isPointerTy()) {
          // In LLVM 18+, pointers are opaque and don't have element types
          // We need to extract type info from debug info instead
          break;
        }

        if (auto *ST = dyn_cast<StructType>(InstType)) {
          if (ST->isOpaque() || ST->getName().empty()) continue;
          std::string TypeName = ST->getName().str();
          if (TypeName.find("struct.") == 0)
            TypeName = TypeName.substr(7);
          else if (TypeName.find("class.") == 0)
            TypeName = TypeName.substr(6);
          UsedTypeNames.insert(TypeName);
        }
      }

      // Also collect types from GEP instructions
      for (const Instruction *I : CombinedSR.Insts) {
        if (auto *GEP = dyn_cast<GetElementPtrInst>(I)) {
          // For opaque pointers (LLVM 18+), we need to get the type from the source element
          Type *SourceTy = GEP->getSourceElementType();
          if (auto *ST = dyn_cast<StructType>(SourceTy)) {
            if (!ST->isOpaque() && !ST->getName().empty()) {
              std::string TypeName = ST->getName().str();
              if (TypeName.find("struct.") == 0)
                TypeName = TypeName.substr(7);
              else if (TypeName.find("class.") == 0)
                TypeName = TypeName.substr(6);
              UsedTypeNames.insert(TypeName);
            }
          }
        }
      }

      // Find debug info for these types
      // Collect all DICompositeType from the module's metadata
      DenseSet<const DICompositeType*> AllCompositeTypes;

      // Method 1: Collect from retainedTypes in compile units
      NamedMDNode *CU_Nodes = M.getNamedMetadata("llvm.dbg.cu");
      if (CU_Nodes) {
        for (unsigned i = 0, e = CU_Nodes->getNumOperands(); i != e; ++i) {
          DICompileUnit *CU = dyn_cast<DICompileUnit>(CU_Nodes->getOperand(i));
          if (!CU) continue;

          for (const DINode *Node : CU->getRetainedTypes()) {
            if (const DICompositeType *CT = dyn_cast<DICompositeType>(Node))
              AllCompositeTypes.insert(CT);
          }
        }
      }

      // Method 2: Scan debug info in the module more thoroughly
      // We need to find all DICompositeTypes, including distinct ones
      // These are often referenced by DILocalVariable or DISubprogram

      // Look through all instructions to find DICompositeType references
      for (const Function &F : M) {
        for (const BasicBlock &BB : F) {
          for (const Instruction &I : BB) {
            if (const DbgDeclareInst *DDI = dyn_cast<DbgDeclareInst>(&I)) {
              if (const DILocalVariable *DV = DDI->getVariable()) {
                if (const DIType *VarType = DV->getType()) {
                  // Walk the type hierarchy to find DICompositeType
                  SmallVector<const DIType*, 8> TypeQueue;
                  TypeQueue.push_back(VarType);
                  while (!TypeQueue.empty()) {
                    const DIType *CurrentType = TypeQueue.pop_back_val();
                    if (const DICompositeType *CT = dyn_cast<DICompositeType>(CurrentType)) {
                      AllCompositeTypes.insert(CT);
                    }
                    // Follow derived types
                    if (const DIDerivedType *DT = dyn_cast<DIDerivedType>(CurrentType)) {
                      if (DT->getBaseType())
                        TypeQueue.push_back(DT->getBaseType());
                    }
                  }
                }
              }
            }
          }
        }
      }


      // Now check each composite type
      for (const DICompositeType *CT : AllCompositeTypes) {
        unsigned Tag = CT->getTag();
        StringRef Name = CT->getName();
        // DW_TAG_structure_type = 0x13, DW_TAG_class_type = 0x02
        if (Tag != 0x13 && Tag != 0x02)
          continue;

        if (VisitedTypes.count(CT)) continue;

        StringRef CTName = CT->getName();
        StringRef CTIdentifier = CT->getIdentifier();

        if (CTName.empty() && !CTIdentifier.empty()) {
          CTName = CTIdentifier;
        }
        if (CTName.empty()) continue;

        // Check if this type is used
        bool IsUsed = false;
        for (const auto &UsedName : UsedTypeNames) {
          // Match both direct name and identifier (which may have C++ mangling)
          if (CTName.contains(UsedName) ||
              (!CTIdentifier.empty() && CTIdentifier.contains(UsedName))) {
            IsUsed = true;
            break;
          }
        }
        if (!IsUsed) {
          continue;
        }

        VisitedTypes.insert(CT);

        const DIFile *DefFile = CT->getFile();
        if (!DefFile) continue;

        StringRef FN = DefFile->getFilename();
        StringRef DIR = DefFile->getDirectory();
        std::string FilePath;

        if (!FN.empty()) {
          if (FN.startswith("/"))
            FilePath = FN.str();
          else if (!DIR.empty())
            FilePath = DIR.str() + "/" + FN.str();
          else
            FilePath = FN.str();
        }

        unsigned DefLine = CT->getLine();
        if (FilePath.empty() || DefLine == 0) continue;

        // Add type definition to the slice
        GlobalFileLineFuncs[FilePath][DefLine].insert("<type-def>");

        // Include the full struct definition (next 20 lines)
        for (int offset = 0; offset <= 20; ++offset) {
          unsigned targetLine = DefLine + offset;
          if (targetLine > 0) {
            GlobalFileLineFuncs[FilePath][targetLine].insert("<type-context>");
          }
        }
      }
    }

    // Print Source Slice (ONLY) to SrcOS (file or cmd)
    if (PrintSourceSlice) {
      const std::vector<OrderedFunctionView> *PreferredOrderPtr =
          PreferredFunctionOrder.empty() ? nullptr : &PreferredFunctionOrder;
      printSourceSliceFromMap(*SrcOS, GlobalFileLineFuncs, GlobalTargetBranches,
                              SourceContext, PreferredOrderPtr);
      SrcOS->flush();
    }

    CmdOS.flush();
    return PreservedAnalyses::all();
  }
};

} // namespace

int main(int argc, const char **argv) {
  cl::ParseCommandLineOptions(argc, argv,
                              "Standalone BranchConditionSlicer\n");

  LLVMContext Context;
  auto M = loadModule(Context, InputBitcode);
  if (!M)
    return 1;

  PassBuilder PB;
  ModuleAnalysisManager MAM;
  PB.registerModuleAnalyses(MAM);

  ModulePassManager MPM;
  MPM.addPass(BranchCondSlicePass());
  MPM.run(*M, MAM);
  return 0;
}
