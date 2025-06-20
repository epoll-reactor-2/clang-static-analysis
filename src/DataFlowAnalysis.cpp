//===- DataflowAnalysis.cpp ---------------------------------------*- C++ -*-===//
//
// Example static analysis pass that tracks unknown sources for allocation
// functions.
//
// This could be extended to support several allocation functions, for
// example malloc, calloc, realloc, Linux kernel functions like
// %resource/device%_%alloc/new%(...).
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"

#include "clang/Analysis/FlowSensitive/DataflowAnalysis.h"
#include "clang/Analysis/FlowSensitive/DataflowAnalysisContext.h"
#include "clang/Analysis/FlowSensitive/WatchedLiteralsSolver.h"
#include "clang/Analysis/FlowSensitive/AdornedCFG.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <optional>

using namespace clang;
using namespace clang::dataflow;
using namespace clang::tooling;
using namespace llvm;

enum class ArgumentOrigin {
  Unknown,
  // Integer literal, always known.
  Constant,
  // Expression with no unknown sources
  // in data dependency chain.
  Deterministic,
  // Expression with unknown source of the
  // data. Possible occurrences:
  // 1. Functions. Note that even if function noted with
  //    __attribute__ ((const)) or __attribute__ ((pure)),
  //    it formally allowed to return undefined results.
  NonDeterministic,
  // Conflicting merge point of the control flow, where
  // one branch is deterministic and second is non-deterministic.
  Conflicting
};

llvm::StringRef originToString(ArgumentOrigin O) {
  switch (O) {
  case ArgumentOrigin::Unknown:
    return "Unknown";
  case ArgumentOrigin::Constant:
    return "Constant";
  case ArgumentOrigin::Deterministic:
    return "Deterministic";
  case ArgumentOrigin::NonDeterministic:
    return "Non‑Deterministic";
  case ArgumentOrigin::Conflicting:
    return "Conflicting";
  }
  llvm_unreachable("Unhandled origin");
};

ArgumentOrigin join(ArgumentOrigin A, ArgumentOrigin B) {
  if (A == B) return A;
  if (A == ArgumentOrigin::Unknown) return B;
  if (B == ArgumentOrigin::Unknown) return A;
  if ((A == ArgumentOrigin::Constant && B == ArgumentOrigin::Deterministic) ||
      (B == ArgumentOrigin::Constant && A == ArgumentOrigin::Deterministic))
    return ArgumentOrigin::Deterministic;
  return ArgumentOrigin::Conflicting;
}

// One element in the whole per-function dataflow lattice.
struct ArgumentLattice {
  // Mapping of variables and their last updated state of the
  // data source. Used to inspect variable status in the expression.
  // Maps are merged once two lattice nodes are joined together.
  llvm::DenseMap<const VarDecl *, ArgumentOrigin> Origins;

  bool operator==(const ArgumentLattice &Other) const {
    return Origins == Other.Origins;
  }

  void join(const ArgumentLattice &Other) {
    for (auto &[Var, Origin] : Other.Origins) {
      Origins[Var] = ::join(Origins[Var], Origin);
    }
  }
};

// Clang does not provide API to determine const-fold
// property for call expression, so we are forced to walk
// AST manually and check.
class ConstFoldCallAnalysis : public RecursiveASTVisitor<ConstFoldCallAnalysis> {
  ASTContext &ASTCtx;
  llvm::SmallVector<llvm::APSInt, 32> Values;
  bool AllEvaluable = true;

public:
  ConstFoldCallAnalysis(ASTContext &Ctx)
    : ASTCtx(Ctx) {}

  // Called for each return statement in a function and
  // collects needed information.
  bool VisitReturnStmt(ReturnStmt *RS) {
    const Expr *Ret = RS->getRetValue();
    if (!Ret)
      return true;

    Ret = Ret->IgnoreParenImpCasts();

    Expr::EvalResult ER;
    if (Ret->EvaluateAsRValue(ER, ASTCtx) && ER.Val.isInt())
      Values.push_back(ER.Val.getInt());
    else
      AllEvaluable = false;
    return true;
  }

  // We assume that function is const-foldable if
  // it returns only one possible value through each
  // return path.
  //
  // Should be called when traverse is finished.
  bool isConstFoldable() const {
    if (!AllEvaluable || Values.empty())
      return false;
    for (const auto &V : Values)
      if (V != Values.front())
        return false;
    return true;
  }
};

class ArgumentAnalysis : public DataflowAnalysis<ArgumentAnalysis, ArgumentLattice> {
  ASTContext &ASTCtx;

public:
  ArgumentAnalysis(ASTContext &Ctx)
    : DataflowAnalysis(Ctx), ASTCtx(Ctx) {}

  ArgumentLattice initialElement() { return ArgumentLattice(); }

  void transfer(const CFGElement &Elt, ArgumentLattice &L, Environment &Env) {
    if (!Elt.getAs<CFGStmt>()) return;

    const Stmt *S = nullptr;
    switch (Elt.getKind()) {
      case CFGElement::Kind::Statement:
        S = Elt.castAs<CFGStmt>().getStmt();
        break;
      default:
        return;
    }

    if (const auto *DS = dyn_cast<DeclStmt>(S)) {
      for (auto *D : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(D)) {
          if (const Expr *Init = VD->getInit()) {
            L.Origins[VD] = classifyExpr(Init, L);
          }
        }
      }
    } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->isAssignmentOp()) {
        const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
        const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

        if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
            ArgumentOrigin Origin = classifyExpr(RHS, L);
            L.Origins[VD] = ::join(L.Origins[VD], Origin);
          }
        }
      }
    }
  }

  ArgumentOrigin classifyCallExpr(const CallExpr *CE) const {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD->hasBody()) {
        const Stmt *Body = FD->getBody();
        ConstFoldCallAnalysis RC(ASTCtx);
        RC.TraverseStmt(const_cast<Stmt *>(Body));

        if (RC.isConstFoldable()) {
          outs() << "Function `" << FD->getName()
                 << "` is const-foldable.\n";
          return ArgumentOrigin::Constant;
        }
      }
    }
    return ArgumentOrigin::NonDeterministic;
  }

  ArgumentOrigin classifyExpr(const Expr *E, const ArgumentLattice &L) const {
    E = E->IgnoreParenImpCasts();

    if (auto *I = dyn_cast<IntegerLiteral>(E))
      return ArgumentOrigin::Constant;

    else if (auto *CE = dyn_cast<ExplicitCastExpr>(E))
      return classifyExpr(CE->getSubExpr(), L);

    else if (auto *CE = dyn_cast<CallExpr>(E))
        return classifyCallExpr(CE);

    else if (auto *BO = dyn_cast<BinaryOperator>(E))
      return ::join(classifyExpr(BO->getLHS(), L), classifyExpr(BO->getRHS(), L));

    else if (auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (auto It = L.Origins.find(VD); It != L.Origins.end())
        return It->second;
      else
        return ArgumentOrigin::Unknown;
    }

    else
      return ArgumentOrigin::Unknown;
  }
};

class ArgumentASTConsumer : public ASTConsumer {
  ASTContext &Ctx;
public:
  explicit ArgumentASTConsumer(ASTContext &Ctx) : Ctx(Ctx) {}

  void HandleTranslationUnit(ASTContext &AC) override {
    for (auto *D : AC.getTranslationUnitDecl()->decls()) {
      if (auto *FD = dyn_cast<FunctionDecl>(D))
        if (FD->hasBody() && !FD->isTemplated())
          analyze(*FD);
    }
  }

  void analyze(const FunctionDecl &FD) {
    DataflowAnalysisContext DACtx(std::make_unique<WatchedLiteralsSolver>());
    auto ACFGOrErr = AdornedCFG::build(FD);
    if (!ACFGOrErr) {
      llvm::errs() << "CFG build failed: " << llvm::toString(ACFGOrErr.takeError()) << "\n";
      return;
    }
    AdornedCFG ACFG = std::move(*ACFGOrErr);

    Environment Env(DACtx, FD);
    ArgumentAnalysis Analysis(Ctx);
    auto StatesOrErr = runDataflowAnalysis(ACFG, Analysis, Env);
    if (!StatesOrErr) {
      llvm::errs() << "Analysis failed: " << llvm::toString(StatesOrErr.takeError()) << "\n";
      return;
    }

    const auto &States = *StatesOrErr;
    const CFG &Cfg = ACFG.getCFG();

    for (const CFGBlock *Block : Cfg) {
      const auto &BlockStateOpt = States[Block->getBlockID()];
      // Unreachable block.
      if (!BlockStateOpt)
        continue;
      const auto &BlockState = *BlockStateOpt;

      for (const auto &Elt : *Block) {
        // We only care about statements.
        if (!Elt.getAs<CFGStmt>())
          continue;

        tryAnalyzeCall(Elt.castAs<CFGStmt>().getStmt(), Analysis, BlockState.Lattice);
      }
    }
  }

  void tryAnalyzeCall(const Stmt *S, ArgumentAnalysis &Analysis, const ArgumentLattice &Lattice) {
    const auto *Call = dyn_cast<CallExpr>(S);
    if (!Call)
      return;

    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier() ||
        Callee->getName() != "malloc")
      return;

    const Expr *SizeArg = Call->getArg(0)->IgnoreParenImpCasts();
    ArgumentOrigin O = Analysis.classifyExpr(SizeArg, Lattice);

    llvm::outs() << "  malloc at ";
    Call->getExprLoc().print(llvm::outs(), Ctx.getSourceManager());
    llvm::outs() << " -> " << originToString(O) << "\n";

  }
};

class ArgumentAction : public ASTFrontendAction {
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef) override {
    return std::make_unique<ArgumentASTConsumer>(CI.getASTContext());
  }
};

int main(int argc, const char **argv) {
  cl::OptionCategory Category("allocation-size-check options");
  auto Exp = CommonOptionsParser::create(argc, argv, Category);
  if (!Exp) {
    llvm::errs() << Exp.takeError() << "\n";
    return 1;
  }

  ClangTool Tool(Exp->getCompilations(), Exp->getSourcePathList());
  return Tool.run(newFrontendActionFactory<ArgumentAction>().get());
}
