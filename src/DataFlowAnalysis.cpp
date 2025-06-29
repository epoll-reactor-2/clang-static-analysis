//===- DataFlowAnalysis.cpp -------------------------------------*- C++ -*-===//
//
// Example static analysis pass that tracks unknown sources for allocation
// functions.
//
// This could be extended to support several allocation functions, for
// example malloc, calloc, realloc, Linux kernel functions like
// %resource/device%_%alloc/new%(...).
//
//===----------------------------------------------------------------------===//

// Wiping away tears, I am forced to do this urbicide
#include "PCH.hpp"

using namespace clang;
using namespace clang::ast_matchers;
namespace dataflow = clang::dataflow;
namespace tooling = clang::tooling;

//===----------------------------------------------------------------------===//
// Lattice definition
//===----------------------------------------------------------------------===//

enum class DynamicSource {
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

llvm::StringRef dynamicSourceToString(DynamicSource O) {
  switch (O) {
  case DynamicSource::Unknown:
    return "unknown";
  case DynamicSource::Constant:
    return "constant";
  case DynamicSource::Deterministic:
    return "deterministic";
  case DynamicSource::NonDeterministic:
    return "non‑deterministic";
  case DynamicSource::Conflicting:
    return "conflicting";
  }
  llvm_unreachable("Unhandled origin");
};

DynamicSource joinSources(DynamicSource A, DynamicSource B) {
  if (A == B) return A;
  if (A == DynamicSource::Unknown) return B;
  if (B == DynamicSource::Unknown) return A;
  if ((A == DynamicSource::Constant && B == DynamicSource::Deterministic) ||
      (B == DynamicSource::Constant && A == DynamicSource::Deterministic))
    return DynamicSource::Deterministic;
  return DynamicSource::Conflicting;
}
// One element in the whole per-function dataflow lattice.
struct DynamicBufferLattice {
  // Mapping of variables and their last updated state of the
  // data source. Used to inspect variable status in the expression.
  // Maps are merged once two lattice nodes are joined together.
  llvm::DenseMap<const VarDecl *, DynamicSource> DeclStates;
  llvm::DenseMap<const VarDecl *, llvm::APSInt> DeclAllocSizes;

  bool operator==(const DynamicBufferLattice &Other) const {
    return DeclStates == Other.DeclStates
        && DeclAllocSizes == Other.DeclAllocSizes;
  }

  void join(const DynamicBufferLattice &Other) {
    for (auto &[Var, Origin] : Other.DeclStates) {
      DeclStates[Var] = joinSources(DeclStates[Var], Origin);
    }
  }
};

//===----------------------------------------------------------------------===//
// Warn API
//===----------------------------------------------------------------------===//

template <unsigned N, typename... Args>
void emitWarning(ASTContext &Ctx, SourceLocation Loc,
                 const char (&FormatString)[N], Args &&... args) {
  DiagnosticsEngine &Diag = Ctx.getDiagnostics();
  unsigned ID = Diag.getCustomDiagID(DiagnosticsEngine::Warning,
                                     FormatString);
  DiagnosticBuilder Builder = Diag.Report(Loc, ID);
  (Builder << ... << std::forward<Args>(args));
}

//===----------------------------------------------------------------------===//
// Function constant fold property
//===----------------------------------------------------------------------===//

// Clang does not provide API to determine const-fold
// property for the functions, so we are forced to walk
// AST manually and check.
//
// Examples:
//
// int _1() { // Const-fold
//   return 100;
// }
//
// int _2(int param) { // Const-fold
//   if (param)
//     return 100;
//   return 100;
// }
//
// int _3(int param) { // Not const-fold
//   if (param)
//     return 100;
//   return 200;
// }
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

//===----------------------------------------------------------------------===//
// Classify expression type
//===----------------------------------------------------------------------===//

static bool isAllocationFunction(const CallExpr *E) {
  const FunctionDecl *Callee = E->getDirectCallee();
  return Callee && Callee->getName() == "malloc";
}

static DynamicSource classifyCallExpr(ASTContext &ASTCtx, const CallExpr *CE) {
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (FD->hasBody()) {
      const Stmt *Body = FD->getBody();
      ConstFoldCallAnalysis RC(ASTCtx);
      RC.TraverseStmt(const_cast<Stmt *>(Body));

      if (RC.isConstFoldable())
        return DynamicSource::Constant;
    }
  }

  return DynamicSource::NonDeterministic;
}

// This function de-facto decides what the kind of expression we have.
static DynamicSource classifyExpr(ASTContext &ASTCtx, const Expr *E, const DynamicBufferLattice &L) {
  E = E->IgnoreParenImpCasts();

  // Integer literal. Always constant, no doubts.
  if (auto *I = dyn_cast<IntegerLiteral>(E))
    return DynamicSource::Constant;

  // Explicit cast. Just determine type of underlying expression.
  if (auto *CE = dyn_cast<ExplicitCastExpr>(E))
    return classifyExpr(ASTCtx, CE->getSubExpr(), L);

  // Function call. May be const-foldable in happy case.
  if (auto *CE = dyn_cast<CallExpr>(E))
    return classifyCallExpr(ASTCtx, CE);

  // Ternary operator. Join both sides.
  if (auto *C = dyn_cast<ConditionalOperator>(E)) {
    return joinSources(
      classifyExpr(ASTCtx, C->getLHS(), L),
      classifyExpr(ASTCtx, C->getRHS(), L)
    );
  }

  // Binary. The result is join of two sides of the expression.
  // If at least one node in binary node has non-deterministic source, the whole
  // expression also will be non-deterministic.
  if (auto *BO = dyn_cast<BinaryOperator>(E))
    return joinSources(
      classifyExpr(ASTCtx, BO->getLHS(), L),
      classifyExpr(ASTCtx, BO->getRHS(), L)
    );

  // Variable declaration. Look up the lattice storage.
  if (auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    auto It = L.DeclStates.find(VD);
    if (It != L.DeclStates.end())
      return It->second;
    else
      // The symbol is defined somewhere, but does not exists in
      // current function context, hence has unknown nature for us. To dig deeper
      // we need inter-function analysis.
      return DynamicSource::NonDeterministic;
  }

  return DynamicSource::Unknown;
}

//===----------------------------------------------------------------------===//
// Update program state
//===----------------------------------------------------------------------===//

// This updates lattice state between data flow transfers.
// Matched AST nodes serves as input data.
// Updated lattice serves as output data.
class DynamicBufferUpdateStep {
  ASTContext &ASTCtx;
DynamicBufferLattice &Lattice;

public:
  DynamicBufferUpdateStep(ASTContext &Ctx, DynamicBufferLattice &L)
    : ASTCtx(Ctx), Lattice(L) {}

  void printLoc(const char *Prefix, SourceLocation Loc) {
    SourceManager &SM = ASTCtx.getSourceManager();
    FullSourceLoc FullLoc(Loc, SM);

    if (FullLoc.isValid()) {
      llvm::outs() << "Got " << Prefix << " at "
                   << SM.getFilename(FullLoc) << ":"
                   << FullLoc.getSpellingLineNumber() << ":"
                   << FullLoc.getSpellingColumnNumber() << "\n";
    }
  }

  std::optional<llvm::APSInt> tryEvalAllocationFunction(const Expr *Value) {
    const auto *Call = dyn_cast<CallExpr>(Value->IgnoreCasts());
    if (!Call) {
      return std::nullopt;
    }

    if (!isAllocationFunction(Call))
      return std::nullopt;

    const Expr *SizeArg = Call->getArg(0)->IgnoreParenImpCasts();
    Expr::EvalResult ER;
    if (SizeArg->EvaluateAsRValue(ER, ASTCtx) && ER.Val.isInt())
      return ER.Val.getInt();

    return std::nullopt;
  }

  void runOnDecl(const VarDecl *Decl, const Expr *Value) {
    Lattice.DeclStates[Decl] = classifyExpr(ASTCtx, Value, Lattice);

    if (auto Result = tryEvalAllocationFunction(Value)) {
      llvm::outs() << "Variable " << Decl->getName() << " has const malloc(" << *Result << ")\n";
      Lattice.DeclAllocSizes[Decl] = *Result;
    }
  }

  void runOnAssign(const BinaryOperator *S) {
    const auto *DRE = dyn_cast<DeclRefExpr>(S->getLHS()->IgnoreParenImpCasts());
    assert(DRE);
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    assert(VD);

    llvm::outs() << "Assignment to variable `" << VD->getName() << "`\n";

    DynamicSource New = classifyExpr(ASTCtx, S->getRHS(), Lattice);
    // NOTE: Should we join or do something else?
    //       Eventually check if this assignment is covered with some
    //       condition.
    Lattice.DeclStates[VD] = joinSources(Lattice.DeclStates[VD], New);
  }

  void verifyIndex(const Expr *Index, const VarDecl *VD) {
    Expr::EvalResult ER;
    if (!Index->EvaluateAsRValue(ER, ASTCtx) && ER.Val.isInt())
      return;

    llvm::outs() << "Array access[" << ER.Val.getInt() << "] to variable `"
                 << VD->getName() << "`\n";
    if (!Lattice.DeclAllocSizes.contains(VD))
      return;

    llvm::APSInt L = ER.Val.getInt();
    llvm::APSInt R = Lattice.DeclAllocSizes[VD];
    if (L >= R) {
      emitWarning(ASTCtx, Index->getExprLoc(),
                  "Out of range! `%0` size equals %1 bytes",
                  VD->getName(), R.getExtValue());
    }
  }

  void runOnArrayAccess(const BinaryOperator *S) {
    const Expr *LHS = S->getLHS()->IgnoreParenImpCasts();

    const auto *ASE = dyn_cast<ArraySubscriptExpr>(LHS);
    assert(ASE);

    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    const Expr *Index = ASE->getIdx()->IgnoreParenImpCasts();

    const auto *DRE = dyn_cast<DeclRefExpr>(Base);
    assert(DRE);
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    assert(VD);

    verifyIndex(Index, VD);
  }
};

//===----------------------------------------------------------------------===//
// AST matcher
//===----------------------------------------------------------------------===//

// Note that this matcher analyzes all declarations and assignments and
// it is designed like this to keep track origins of each variable, since
// each one can be theoretically used in the allocation function
// size calculation.
class ASTMatcher : public MatchFinder::MatchCallback {
  ASTContext &ASTCtx;
  DynamicBufferLattice &L;

public:
  ASTMatcher(ASTContext &Ctx, DynamicBufferLattice &L)
    : ASTCtx(Ctx), L(L) {}

  void run(const MatchFinder::MatchResult &R) override {
    DynamicBufferUpdateStep Step(ASTCtx, L);

    if (const auto *VD = R.Nodes.getNodeAs<VarDecl>("analysis_decl"))
      Step.runOnDecl(VD, R.Nodes.getNodeAs<Expr>("value"));

    else if (const auto *A = R.Nodes.getNodeAs<BinaryOperator>("analysis_assign"))
      Step.runOnAssign(A);

    else if (const auto *A = R.Nodes.getNodeAs<BinaryOperator>("analysis_array_access"))
      Step.runOnArrayAccess(A);
  }
};

//===----------------------------------------------------------------------===//
// Data flow analyzer
//===----------------------------------------------------------------------===//

class DynamicBufferDataflowAnalysis
  : public dataflow::DataflowAnalysis<DynamicBufferDataflowAnalysis, DynamicBufferLattice>
{
  ASTContext &ASTCtx;

  StatementMatcher makeDeclMatcher() {
    return declStmt(
      has(varDecl(
        hasInitializer(expr().bind("value"))
      ).bind("analysis_decl"))
    );
  }

  StatementMatcher makeAssignMatcher() {
    return binaryOperator(
      hasOperatorName("="),
      hasLHS(ignoringParenImpCasts(
        declRefExpr(to(varDecl().bind("var")))
      )),
      hasRHS(expr().bind("value"))
    ).bind("analysis_assign");
  }

  StatementMatcher makeArrayAccessMatcher() {
    return binaryOperator(
      hasOperatorName("="),
      hasLHS(ignoringParenImpCasts(
        arraySubscriptExpr(
          hasBase(ignoringParenImpCasts(
            declRefExpr(to(varDecl().bind("var")))
          )),
          hasIndex(expr().bind("index"))
        )
      )),
      hasRHS(expr().bind("value"))
    ).bind("analysis_array_access");
  }

  const StatementMatcher UpdateMatcher = stmt(anyOf(
    makeDeclMatcher(),
    makeAssignMatcher(),
    makeArrayAccessMatcher()
  ));

public:
  DynamicBufferDataflowAnalysis(ASTContext &ASTCtx)
    : DataflowAnalysis(ASTCtx), ASTCtx(ASTCtx) {}

  DynamicBufferLattice initialElement() { return DynamicBufferLattice(); }

  // Transfer updates abstract program state based the semantics of
  // the current CFG element.
  //
  // The state recorded to the lattice element, which stores actual status
  // of each variable (constant/non-deterministic/unknown). The information
  // collected there is used after dataflow analysis is done.
  void transfer(const CFGElement &Elt, DynamicBufferLattice &L, dataflow::Environment &Env) {
    if (!Elt.getAs<CFGStmt>())
      return;

    const Stmt *S = Elt.castAs<CFGStmt>().getStmt();

    ASTMatcher Matcher(ASTCtx, L);
    MatchFinder Finder;
    Finder.addMatcher(UpdateMatcher, &Matcher);
    Finder.match(*S, ASTCtx);
  }
};

//===----------------------------------------------------------------------===//
// Data flow analyzer driver
//===----------------------------------------------------------------------===//

class DynamicBufferAnalyzeAction {
  using AnalysisResult =
    std::vector<
      std::optional<
        dataflow::DataflowAnalysisState<DynamicBufferLattice>>>;
  ASTContext &ASTCtx;

public:
  DynamicBufferAnalyzeAction(ASTContext &ASTCtx)
    : ASTCtx(ASTCtx) {}

  // This function
  // 1. prepares Adorned CFG of the function,
  // 2. runs given data flow analyzer,
  // 3. inspects its results and eventually do something
  //    with given data.
  void analyze(const FunctionDecl &Decl) {
    // Step 1. Prepare ACFG.
    dataflow::DataflowAnalysisContext DACtx(std::make_unique<dataflow::WatchedLiteralsSolver>());
    auto ACFGOrErr = dataflow::AdornedCFG::build(Decl);
    if (!ACFGOrErr) {
      llvm::errs() << "CFG build failed: " << llvm::toString(ACFGOrErr.takeError()) << "\n";
      return;
    }
    dataflow::AdornedCFG ACFG = std::move(*ACFGOrErr);

    // Step 2. Run data flow analysis pass.
    dataflow::Environment Env(DACtx, Decl);
    DynamicBufferDataflowAnalysis Analysis(ASTCtx);
    auto StatesOrErr = runDataflowAnalysis(ACFG, Analysis, Env);
    if (!StatesOrErr) {
      llvm::errs() << "Analysis failed: " << llvm::toString(StatesOrErr.takeError()) << "\n";
      return;
    }

    // Step 3. Inspect analysis results.
    //
    // This step is useful if we have to make post-analysis
    // judgements. In this example it is not needed.
    //
    // const AnalysisResult &States = *StatesOrErr;
    // inspectDataflowStates(Analysis, ACFG, States);
  }

  void inspectDataflowStates(DynamicBufferDataflowAnalysis &Analysis, dataflow::AdornedCFG &ACFG, const AnalysisResult &States) {
    const CFG &CFG = ACFG.getCFG();

    for (const CFGBlock *Block : CFG) {
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

  void tryAnalyzeCall(const Stmt *S, DynamicBufferDataflowAnalysis &Analysis, const DynamicBufferLattice &Lattice) {
    const auto *Call = dyn_cast<CallExpr>(S);
    if (!Call)
      return;

    if (!isAllocationFunction(Call))
      return;

    const Expr *SizeArg = Call->getArg(0)->IgnoreParenImpCasts();
    // This classification shows us post factum status of the variable.
    // Initially it also done in AST matcher.
    DynamicSource O = classifyExpr(ASTCtx, SizeArg, Lattice);

    emitWarning(ASTCtx, Call->getExprLoc(),
      "malloc size argument is %0", dynamicSourceToString(O));
  }
};

//===----------------------------------------------------------------------===//
// AST Consumer
//===----------------------------------------------------------------------===//

class DynamicBufferASTConsumer : public ASTConsumer {
  ASTContext &ASTCtx;

public:
  DynamicBufferASTConsumer(ASTContext &ASTCtx)
    : ASTCtx(ASTCtx) {}

  void HandleTranslationUnit(ASTContext &Ctx) override {
    DynamicBufferAnalyzeAction Action(ASTCtx);

    for (auto *D : Ctx.getTranslationUnitDecl()->decls()) {
      if (auto *FD = dyn_cast<FunctionDecl>(D))
        if (FD->hasBody()) {
          Action.analyze(*FD);
        }
    }
  }
};

//===----------------------------------------------------------------------===//
// Driver code
//===----------------------------------------------------------------------===//

class DynamicBufferAction : public ASTFrontendAction {
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef) override {
    return std::make_unique<DynamicBufferASTConsumer>(CI.getASTContext());
  }
};

int main(int argc, const char **argv) {
  llvm::cl::OptionCategory Category("dynamic-buffer-check options");
  auto Exp = tooling::CommonOptionsParser::create(argc, argv, Category);
  if (!Exp) {
    llvm::errs() << Exp.takeError() << "\n";
    return 1;
  }

  tooling::ClangTool Tool(Exp->getCompilations(), Exp->getSourcePathList());
  return Tool.run(tooling::newFrontendActionFactory<DynamicBufferAction>().get());
}
