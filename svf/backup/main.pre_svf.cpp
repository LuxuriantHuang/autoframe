#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <string>
#include <system_error>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace llvm;

namespace {

struct BasicBlockInfo {
  uint32_t Id = 0;
  uint32_t RandId = 0;
  uint32_t FunctionId = 0;
  uint32_t LineStart = 0;
  uint32_t LineEnd = 0;
  std::vector<uint32_t> Successors;
  std::vector<uint32_t> Calls;
  bool HasIndirectCall = false;
};

struct FunctionInfo {
  uint32_t Id = 0;
  std::string Name;
  std::string FileName;
  uint32_t LineStart = 0;
  uint32_t LineEnd = 0;
  uint32_t EntryBlockLinearId = 0;
  uint32_t EntryBlockRandId = 0;
  uint32_t BlockNum = 0;
  std::vector<uint32_t> Calls;
  std::vector<uint32_t> Refs;
  bool IsDeclaration = false;
};

struct DirectCallSite {
  const Function *Caller = nullptr;
  const CallBase *CB = nullptr;
};

struct IndirectCallSite {
  const Function *Caller = nullptr;
  const BasicBlock *BB = nullptr;
  const CallBase *CB = nullptr;
  uint32_t FunctionId = 0;
  uint32_t BlockId = 0;
};

static cl::opt<std::string> InputPath(
    cl::Positional, cl::desc("<input .ll or .bc>"), cl::Required);

static cl::opt<std::string> OutputDir(
    "o", cl::desc("Output directory"), cl::init("output"));

static cl::opt<bool> EmitDot("emit-dot", cl::desc("Emit DOT files"), cl::init(true));

static std::string sanitize(StringRef Name) {
  std::string Out;
  Out.reserve(Name.size());
  for (char C : Name) {
    if (std::isalnum(static_cast<unsigned char>(C)) || C == '_') {
      Out.push_back(C);
    } else {
      Out.push_back('_');
    }
  }
  if (Out.empty()) {
    Out = "anon";
  }
  return Out;
}

static uint32_t stableRandId(StringRef S) {
  uint32_t Hash = 2166136261u;
  for (unsigned char C : S) {
    Hash ^= C;
    Hash *= 16777619u;
  }
  return Hash ? Hash : 1u;
}

static void getDebugLoc(const Instruction &I, std::string &FileName,
                        uint32_t &Line) {
  Line = 0;
  FileName.clear();

  if (const DILocation *Loc = I.getDebugLoc()) {
    Line = Loc->getLine();
    FileName = Loc->getFilename().str();
    if (FileName.empty()) {
      if (const DILocation *InlinedAt = Loc->getInlinedAt()) {
        Line = InlinedAt->getLine();
        FileName = InlinedAt->getFilename().str();
      }
    }
  }
}

static std::unique_ptr<Module> loadModule(LLVMContext &Context,
                                          const std::string &Path) {
  SMDiagnostic Err;
  auto ModuleOrErr = parseIRFile(Path, Err, Context);
  if (ModuleOrErr) {
    return ModuleOrErr;
  }

  auto BufferOrErr = MemoryBuffer::getFile(Path);
  if (!BufferOrErr) {
    errs() << "failed to read input: " << Path << "\n";
    return nullptr;
  }

  Expected<std::unique_ptr<Module>> BitcodeModule =
      parseBitcodeFile(BufferOrErr.get()->getMemBufferRef(), Context);
  if (!BitcodeModule) {
    Err.print("ir_graph_extractor", errs());
    logAllUnhandledErrors(BitcodeModule.takeError(), errs(),
                          "bitcode parse failed: ");
    return nullptr;
  }
  return std::move(*BitcodeModule);
}

static bool ensureDir(StringRef Dir) {
  std::error_code EC = sys::fs::create_directories(Dir);
  if (EC) {
    errs() << "failed to create output directory: " << Dir << ": " << EC.message()
           << "\n";
    return false;
  }
  return true;
}

static void dedup(std::vector<uint32_t> &Values) {
  std::sort(Values.begin(), Values.end());
  Values.erase(std::unique(Values.begin(), Values.end()), Values.end());
}

static json::Array toJsonArray(const std::vector<uint32_t> &Values) {
  json::Array Out;
  for (uint32_t V : Values) {
    Out.push_back(V);
  }
  return Out;
}

static void writeCallGraphDot(StringRef Path,
                              const std::vector<FunctionInfo> &Functions) {
  std::error_code EC;
  raw_fd_ostream OS(Path, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "failed to open " << Path << ": " << EC.message() << "\n";
    return;
  }

  OS << "digraph callgraph {\n";
  OS << "  rankdir=LR;\n";
  for (const auto &F : Functions) {
    OS << "  \"" << F.Name << "\";\n";
  }
  for (const auto &F : Functions) {
    for (uint32_t CalleeId : F.Calls) {
      OS << "  \"" << F.Name << "\" -> \"" << Functions[CalleeId].Name
         << "\" [label=\"call\"];\n";
    }
    for (uint32_t RefId : F.Refs) {
      OS << "  \"" << F.Name << "\" -> \"" << Functions[RefId].Name
         << "\" [label=\"ref\"];\n";
    }
  }
  OS << "}\n";
}

static void writeFunctionCfgDot(StringRef Path, const Function &F,
                                const std::vector<BasicBlockInfo> &Blocks,
                                const std::vector<const BasicBlock *> &Order,
                                const std::unordered_map<const BasicBlock *, uint32_t> &IdMap) {
  std::error_code EC;
  raw_fd_ostream OS(Path, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "failed to open " << Path << ": " << EC.message() << "\n";
    return;
  }

  OS << "digraph \"" << F.getName() << "\" {\n";
  OS << "  node [shape=box];\n";
  for (const BasicBlock *BB : Order) {
    const auto &Info = Blocks[IdMap.at(BB)];
    OS << "  \"" << Info.Id << "\" [label=\"bb" << Info.Id << "\\n"
       << Info.LineStart << "-" << Info.LineEnd << "\"];\n";
  }
  for (const BasicBlock *BB : Order) {
    const auto &Info = Blocks[IdMap.at(BB)];
    for (uint32_t SuccId : Info.Successors) {
      OS << "  \"" << Info.Id << "\" -> \"" << SuccId << "\";\n";
    }
  }
  OS << "}\n";
}

class Analyzer {
public:
  explicit Analyzer(Module &M) : M(M) {}

  void run() {
    seedDefinedFunctions();
    seedBasicBlocks();
    recordSuccessors();
    recordCallsAndRefs();
    inferBasicBlockLines();
    resolveIndirectCalls();
    finalizeFunctions();
    rebuildFunctionLinesFromBlocks();
  }

  const std::vector<FunctionInfo> &getFunctions() const { return Functions; }
  const std::vector<BasicBlockInfo> &getBasicBlocks() const { return BasicBlocks; }
  const std::unordered_map<const BasicBlock *, uint32_t> &getBasicBlockMap() const {
    return BasicBlockMap;
  }

private:
  Module &M;
  std::vector<FunctionInfo> Functions;
  std::vector<BasicBlockInfo> BasicBlocks;
  std::unordered_map<const Function *, uint32_t> FunctionMap;
  std::unordered_map<const BasicBlock *, uint32_t> BasicBlockMap;
  std::unordered_map<const Function *, std::vector<DirectCallSite>> DirectCallers;
  std::vector<IndirectCallSite> IndirectCalls;
  std::unordered_map<const Value *, std::set<const Function *>> ResolveCache;
  std::unordered_set<const Value *> Resolving;

  static bool shouldSkipFunction(const Function &F) {
    if (F.isIntrinsic()) {
      return true;
    }

    static const char *Blacklist[] = {
        "__log",
        "asan.",
        "llvm.",
        "sancov.",
        "__ubsan_handle_",
        "__sanitizer_cov_function_entry",
    };

    for (const char *Prefix : Blacklist) {
      if (F.getName().startswith(Prefix)) {
        return true;
      }
    }
    return false;
  }

  uint32_t recordFunction(const Function &F) {
    auto It = FunctionMap.find(&F);
    if (It != FunctionMap.end()) {
      return It->second;
    }

    uint32_t Id = static_cast<uint32_t>(Functions.size());
    FunctionInfo Info;
    Info.Id = Id;
    Info.Name = demangle(F.getName().str().c_str());
    Info.IsDeclaration = F.isDeclaration();
    Info.BlockNum = F.isDeclaration() ? 0u : static_cast<uint32_t>(F.size());

    if (const DISubprogram *SP = F.getSubprogram()) {
      Info.LineStart = SP->getLine();
      Info.FileName = SP->getFilename().str();
    }

    if (!F.isDeclaration()) {
      const BasicBlock &Entry = F.getEntryBlock();
      SmallString<128> Key;
      Key += F.getName();
      Key += "::";
      if (Entry.hasName()) {
        Key += Entry.getName();
      } else {
        Key += "entry";
      }
      Info.EntryBlockRandId = stableRandId(Key);
    }

    Functions.push_back(std::move(Info));
    FunctionMap[&F] = Id;
    return Id;
  }

  void seedDefinedFunctions() {
    for (const Function &F : M) {
      if (shouldSkipFunction(F)) {
        continue;
      }
      recordFunction(F);
    }
  }

  void seedBasicBlocks() {
    for (const Function &F : M) {
      if (shouldSkipFunction(F) || F.isDeclaration()) {
        continue;
      }

      uint32_t FuncId = recordFunction(F);
      for (const BasicBlock &BB : F) {
        uint32_t BlockId = static_cast<uint32_t>(BasicBlocks.size());
        SmallString<128> Key;
        Key += F.getName();
        Key += "::";
        if (BB.hasName()) {
          Key += BB.getName();
        } else {
          Key += Twine(BlockId).str();
        }

        BasicBlockInfo Info;
        Info.Id = BlockId;
        Info.RandId = stableRandId(Key);
        Info.FunctionId = FuncId;

        bool HasDebug = false;
        for (const Instruction &I : BB) {
          std::string FileName;
          uint32_t Line = 0;
          getDebugLoc(I, FileName, Line);
          if (Line == 0) {
            continue;
          }
          HasDebug = true;
          if (Info.LineStart == 0 || Line < Info.LineStart) {
            Info.LineStart = Line;
          }
          if (Line > Info.LineEnd) {
            Info.LineEnd = Line;
          }
        }
        if (!HasDebug) {
          Info.LineStart = 0;
          Info.LineEnd = 0;
        }

        BasicBlocks.push_back(std::move(Info));
        BasicBlockMap[&BB] = BlockId;
      }

      Functions[FuncId].EntryBlockLinearId = BasicBlockMap.at(&F.getEntryBlock());
      Functions[FuncId].EntryBlockRandId =
          BasicBlocks[Functions[FuncId].EntryBlockLinearId].RandId;
    }
  }

  void recordSuccessors() {
    for (const Function &F : M) {
      if (shouldSkipFunction(F) || F.isDeclaration()) {
        continue;
      }

      std::queue<const BasicBlock *> Q;
      std::set<uint32_t> Seen;
      const BasicBlock *Entry = &F.getEntryBlock();
      Q.push(Entry);
      Seen.insert(BasicBlockMap.at(Entry));

      while (!Q.empty()) {
        const BasicBlock *BB = Q.front();
        Q.pop();
        uint32_t BlockId = BasicBlockMap.at(BB);
        auto &Info = BasicBlocks[BlockId];

        for (const BasicBlock *Succ : successors(BB)) {
          uint32_t SuccId = BasicBlockMap.at(Succ);
          Info.Successors.push_back(SuccId);
          if (!Seen.count(SuccId)) {
            Seen.insert(SuccId);
            Q.push(Succ);
          }
        }
      }
    }
  }

  static bool isNoOpCastOrGep(const Value *V) {
    if (const auto *CE = dyn_cast<ConstantExpr>(V)) {
      switch (CE->getOpcode()) {
      case Instruction::BitCast:
      case Instruction::AddrSpaceCast:
      case Instruction::GetElementPtr:
        return true;
      default:
        return false;
      }
    }

    if (const auto *Op = dyn_cast<Operator>(V)) {
      switch (Op->getOpcode()) {
      case Instruction::BitCast:
      case Instruction::AddrSpaceCast:
      case Instruction::GetElementPtr:
        return true;
      default:
        return false;
      }
    }
    return false;
  }

  static const Value *stripValueCasts(const Value *V) {
    const Value *Current = V;
    while (Current && isNoOpCastOrGep(Current)) {
      if (const auto *CE = dyn_cast<ConstantExpr>(Current)) {
        Current = CE->getOperand(0);
        continue;
      }
      if (const auto *Op = dyn_cast<Operator>(Current)) {
        Current = Op->getOperand(0);
        continue;
      }
      break;
    }
    return Current;
  }

  std::set<const Function *> resolveArgumentTargets(const Argument &Arg,
                                                    unsigned Depth) {
    std::set<const Function *> Result;
    if (Depth > 8) {
      return Result;
    }

    auto It = DirectCallers.find(Arg.getParent());
    if (It == DirectCallers.end()) {
      return Result;
    }

    unsigned ArgNo = Arg.getArgNo();
    for (const DirectCallSite &Site : It->second) {
      if (!Site.CB || ArgNo >= Site.CB->arg_size()) {
        continue;
      }
      auto Nested =
          resolveValueToFunctions(Site.CB->getArgOperand(ArgNo), Depth + 1);
      Result.insert(Nested.begin(), Nested.end());
    }
    return Result;
  }

  std::set<const Function *> resolveMemoryObjectFunctions(const Value *Ptr,
                                                          unsigned Depth) {
    std::set<const Function *> Result;
    Ptr = stripValueCasts(Ptr);
    if (!Ptr || Depth > 8) {
      return Result;
    }

    if (const auto *GV = dyn_cast<GlobalVariable>(Ptr)) {
      if (GV->hasInitializer()) {
        auto InitTargets =
            resolveValueToFunctions(GV->getInitializer(), Depth + 1);
        Result.insert(InitTargets.begin(), InitTargets.end());
      }
    }

    for (const User *U : Ptr->users()) {
      if (const auto *SI = dyn_cast<StoreInst>(U)) {
        if (stripValueCasts(SI->getPointerOperand()) != Ptr) {
          continue;
        }
        auto Stored = resolveValueToFunctions(SI->getValueOperand(), Depth + 1);
        Result.insert(Stored.begin(), Stored.end());
        continue;
      }

      if (const auto *CE = dyn_cast<ConstantExpr>(U)) {
        for (const User *CEUser : CE->users()) {
          if (const auto *SI = dyn_cast<StoreInst>(CEUser)) {
            if (stripValueCasts(SI->getPointerOperand()) != CE) {
              continue;
            }
            auto Stored =
                resolveValueToFunctions(SI->getValueOperand(), Depth + 1);
            Result.insert(Stored.begin(), Stored.end());
          }
        }
      }
    }

    if (const auto *Arg = dyn_cast<Argument>(Ptr)) {
      auto ThroughArg = resolveArgumentTargets(*Arg, Depth + 1);
      Result.insert(ThroughArg.begin(), ThroughArg.end());
    }

    return Result;
  }

  std::set<const Function *> resolveValueToFunctions(const Value *V,
                                                     unsigned Depth = 0) {
    std::set<const Function *> Result;
    if (!V || Depth > 8) {
      return Result;
    }

    V = stripValueCasts(V);
    auto CacheIt = ResolveCache.find(V);
    if (CacheIt != ResolveCache.end()) {
      return CacheIt->second;
    }

    if (!Resolving.insert(V).second) {
      return Result;
    }

    if (const auto *F = dyn_cast<Function>(V)) {
      if (!shouldSkipFunction(*F)) {
        Result.insert(F);
      }
    } else if (const auto *GA = dyn_cast<GlobalAlias>(V)) {
      auto Nested = resolveValueToFunctions(GA->getAliasee(), Depth + 1);
      Result.insert(Nested.begin(), Nested.end());
    } else if (const auto *Arg = dyn_cast<Argument>(V)) {
      auto Nested = resolveArgumentTargets(*Arg, Depth + 1);
      Result.insert(Nested.begin(), Nested.end());
    } else if (const auto *PN = dyn_cast<PHINode>(V)) {
      for (const Value *Incoming : PN->incoming_values()) {
        auto Nested = resolveValueToFunctions(Incoming, Depth + 1);
        Result.insert(Nested.begin(), Nested.end());
      }
    } else if (const auto *SI = dyn_cast<SelectInst>(V)) {
      auto TrueTargets = resolveValueToFunctions(SI->getTrueValue(), Depth + 1);
      auto FalseTargets =
          resolveValueToFunctions(SI->getFalseValue(), Depth + 1);
      Result.insert(TrueTargets.begin(), TrueTargets.end());
      Result.insert(FalseTargets.begin(), FalseTargets.end());
    } else if (const auto *LI = dyn_cast<LoadInst>(V)) {
      auto MemoryTargets =
          resolveMemoryObjectFunctions(LI->getPointerOperand(), Depth + 1);
      Result.insert(MemoryTargets.begin(), MemoryTargets.end());
    } else if (const auto *CE = dyn_cast<ConstantExpr>(V)) {
      if (CE->getOpcode() == Instruction::Select && CE->getNumOperands() >= 3) {
        auto TrueTargets = resolveValueToFunctions(CE->getOperand(1), Depth + 1);
        auto FalseTargets =
            resolveValueToFunctions(CE->getOperand(2), Depth + 1);
        Result.insert(TrueTargets.begin(), TrueTargets.end());
        Result.insert(FalseTargets.begin(), FalseTargets.end());
      }
    }

    Resolving.erase(V);
    ResolveCache[V] = Result;
    return Result;
  }

  void recordResolvedTargets(uint32_t FunctionId, uint32_t BlockId,
                             const std::set<const Function *> &Targets) {
    (void)BlockId;
    for (const Function *Target : Targets) {
      if (shouldSkipFunction(*Target)) {
        continue;
      }
      uint32_t TargetId = recordFunction(*Target);
      Functions[FunctionId].Refs.push_back(TargetId);
    }
  }

  void recordCallsAndRefs() {
    for (const Function &F : M) {
      if (shouldSkipFunction(F) || F.isDeclaration()) {
        continue;
      }

      uint32_t FuncId = FunctionMap.at(&F);

      for (const BasicBlock &BB : F) {
        uint32_t BlockId = BasicBlockMap.at(&BB);
        auto &BlockInfo = BasicBlocks[BlockId];

        for (const Instruction &I : BB) {
          const auto *CB = dyn_cast<CallBase>(&I);
          if (!CB) {
            continue;
          }

          if (const Function *Callee = CB->getCalledFunction()) {
            if (shouldSkipFunction(*Callee)) {
              continue;
            }
            uint32_t CalleeId = recordFunction(*Callee);
            Functions[FuncId].Calls.push_back(CalleeId);
            BlockInfo.Calls.push_back(CalleeId);
            DirectCallers[Callee].push_back({&F, CB});
            continue;
          }

          BlockInfo.HasIndirectCall = true;
          IndirectCalls.push_back({&F, &BB, CB, FuncId, BlockId});
        }
      }
    }
  }

  void resolveIndirectCalls() {
    for (const auto &Site : IndirectCalls) {
      auto Targets = resolveValueToFunctions(Site.CB->getCalledOperand(), 0);
      recordResolvedTargets(Site.FunctionId, Site.BlockId, Targets);

      if (!Targets.empty()) {
        continue;
      }

      for (const Use &Op : Site.CB->operands()) {
        auto Refs = resolveValueToFunctions(Op.get(), 0);
        recordResolvedTargets(Site.FunctionId, Site.BlockId, Refs);
      }
    }
  }

  void rebuildFunctionLinesFromBlocks() {
    for (const auto &Pair : FunctionMap) {
      const Function &F = *Pair.first;
      if (F.isDeclaration()) {
        continue;
      }

      FunctionInfo &Info = Functions[Pair.second];
      for (const BasicBlock &BB : F) {
        const auto &BBInfo = BasicBlocks[BasicBlockMap.at(&BB)];
        if (BBInfo.LineStart != 0 &&
            (Info.LineStart == 0 || BBInfo.LineStart < Info.LineStart)) {
          Info.LineStart = BBInfo.LineStart;
        }
        if (BBInfo.LineEnd > Info.LineEnd) {
          Info.LineEnd = BBInfo.LineEnd;
        }
      }
    }
  }

  void finalizeFunctions() {
    for (FunctionInfo &Info : Functions) {
      dedup(Info.Calls);
      dedup(Info.Refs);
    }

    for (BasicBlockInfo &Info : BasicBlocks) {
      dedup(Info.Successors);
      dedup(Info.Calls);
    }

    for (const auto &Pair : FunctionMap) {
      const Function &F = *Pair.first;
      FunctionInfo &Info = Functions[Pair.second];

      if (F.isDeclaration()) {
        continue;
      }

      uint32_t MaxLine = Info.LineStart;
      if (Info.FileName.empty()) {
        for (const BasicBlock &BB : F) {
          for (const Instruction &I : BB) {
            std::string FileName;
            uint32_t Line = 0;
            getDebugLoc(I, FileName, Line);
            if (!FileName.empty()) {
              Info.FileName = FileName;
            }
            if (Line > 0) {
              if (Info.LineStart == 0 || Line < Info.LineStart) {
                Info.LineStart = Line;
              }
              if (Line > MaxLine) {
                MaxLine = Line;
              }
            }
          }
        }
      } else {
        for (const BasicBlock &BB : F) {
          for (const Instruction &I : BB) {
            std::string UnusedFileName;
            uint32_t Line = 0;
            getDebugLoc(I, UnusedFileName, Line);
            if (Line > 0) {
              if (Info.LineStart == 0 || Line < Info.LineStart) {
                Info.LineStart = Line;
              }
              if (Line > MaxLine) {
                MaxLine = Line;
              }
            }
          }
        }
      }
      Info.LineEnd = MaxLine;
    }
  }

  void inferBasicBlockLines() {
    for (const auto &Pair : FunctionMap) {
      const Function &F = *Pair.first;
      if (F.isDeclaration()) {
        continue;
      }

      const FunctionInfo &FuncInfo = Functions[Pair.second];
      for (const BasicBlock &BB : F) {
        uint32_t BlockId = BasicBlockMap.at(&BB);
        auto &Info = BasicBlocks[BlockId];
        if (Info.LineStart != 0 || Info.LineEnd != 0) {
          continue;
        }

        if (FuncInfo.LineStart != 0) {
          Info.LineStart = FuncInfo.LineStart;
          Info.LineEnd = FuncInfo.LineStart;
        }

        bool Inferred = false;
        for (const BasicBlock *Pred : predecessors(&BB)) {
          uint32_t PredId = BasicBlockMap.at(Pred);
          if (BasicBlocks[PredId].LineStart != 0) {
            Info.LineStart = BasicBlocks[PredId].LineStart;
            Info.LineEnd = BasicBlocks[PredId].LineEnd;
            Inferred = true;
            break;
          }
        }

        if (!Inferred) {
          for (const BasicBlock *Succ : successors(&BB)) {
            uint32_t SuccId = BasicBlockMap.at(Succ);
            if (BasicBlocks[SuccId].LineStart != 0) {
              Info.LineStart = BasicBlocks[SuccId].LineStart;
              Info.LineEnd = BasicBlocks[SuccId].LineEnd;
              break;
            }
          }
        }
      }
    }
  }
};

static void writeStaticJson(StringRef Path, const std::vector<FunctionInfo> &Functions,
                            const std::vector<BasicBlockInfo> &BasicBlocks) {
  json::Array FunctionEntries;
  for (const auto &F : Functions) {
    json::Object Entry;
    Entry["id"] = F.Id;
    Entry["name"] = json::isUTF8(F.Name) ? F.Name : "";
    Entry["calls"] = toJsonArray(F.Calls);
    Entry["refs"] = toJsonArray(F.Refs);
    Entry["lineStart"] = F.LineStart;
    Entry["lineEnd"] = F.LineEnd;
    Entry["entry_block_linear_id"] = F.EntryBlockLinearId;
    Entry["entry_block_rand_id"] = F.EntryBlockRandId;
    Entry["block_num"] = F.BlockNum;
    if (!F.FileName.empty()) {
      Entry["file_name"] = F.FileName;
    }
    FunctionEntries.push_back(std::move(Entry));
  }

  json::Array BlockEntries;
  for (const auto &BB : BasicBlocks) {
    json::Object Entry;
    Entry["id"] = BB.Id;
    Entry["rand_id"] = BB.RandId;
    Entry["lineStart"] = BB.LineStart;
    Entry["lineEnd"] = BB.LineEnd;
    Entry["successors"] = toJsonArray(BB.Successors);
    Entry["calls"] = toJsonArray(BB.Calls);
    Entry["function"] = BB.FunctionId;
    BlockEntries.push_back(std::move(Entry));
  }

  json::Object Root;
  Root["basic_blocks"] = std::move(BlockEntries);
  Root["functions"] = std::move(FunctionEntries);

  std::error_code EC;
  raw_fd_ostream OS(Path, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "failed to open " << Path << ": " << EC.message() << "\n";
    return;
  }
  OS << json::Value(std::move(Root));
}

static void emitDotFiles(StringRef BaseDir, const Module &M,
                         const std::vector<FunctionInfo> &Functions,
                         const std::vector<BasicBlockInfo> &Blocks,
                         const std::unordered_map<const BasicBlock *, uint32_t> &IdMap) {
  SmallString<256> CfgDir(BaseDir);
  sys::path::append(CfgDir, "cfg");
  if (!ensureDir(CfgDir)) {
    return;
  }

  for (const Function &F : M) {
    if (F.isDeclaration() || F.isIntrinsic()) {
      continue;
    }

    std::vector<const BasicBlock *> Order;
    for (const BasicBlock &BB : F) {
      Order.push_back(&BB);
    }

    SmallString<256> DotPath(CfgDir);
    sys::path::append(DotPath, sanitize(F.getName()) + ".dot");
    writeFunctionCfgDot(DotPath, F, Blocks, Order, IdMap);
  }

  SmallString<256> CallGraphPath(BaseDir);
  sys::path::append(CallGraphPath, "callgraph.dot");
  writeCallGraphDot(CallGraphPath, Functions);
}

} // namespace

int main(int argc, const char **argv) {
  cl::ParseCommandLineOptions(argc, argv, "LLVM IR CFG and call graph extractor\n");

  LLVMContext Context;
  auto M = loadModule(Context, InputPath);
  if (!M) {
    return 1;
  }

  if (!ensureDir(OutputDir)) {
    return 1;
  }

  Analyzer Analyzer(*M);
  Analyzer.run();

  SmallString<256> StaticJsonPath(OutputDir);
  sys::path::append(StaticJsonPath, "static.json");
  writeStaticJson(StaticJsonPath, Analyzer.getFunctions(), Analyzer.getBasicBlocks());

  if (EmitDot) {
    emitDotFiles(OutputDir, *M, Analyzer.getFunctions(), Analyzer.getBasicBlocks(),
                 Analyzer.getBasicBlockMap());
  }

  outs() << "analysis finished\n";
  outs() << "  module: " << M->getName() << "\n";
  outs() << "  output: " << OutputDir << "\n";
  outs() << "  functions: " << Analyzer.getFunctions().size() << "\n";
  outs() << "  basic_blocks: " << Analyzer.getBasicBlocks().size() << "\n";
  return 0;
}
