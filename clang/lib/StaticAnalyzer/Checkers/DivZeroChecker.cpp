//== DivZeroChecker.cpp - Division by zero checker --------------*- C++ -*--==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This defines DivZeroChecker, a builtin check in ExprEngine that performs
// checks for division by zeros.
//
//===----------------------------------------------------------------------===//

#include "Taint.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <iostream>

using namespace std;
using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class DivZeroChecker : public Checker< check::PreStmt<CXXMemberCallExpr> > {
  mutable std::unique_ptr<BuiltinBug> BT;
  void reportBug(const char *Msg, ProgramStateRef StateZero, CheckerContext &C,
                 std::unique_ptr<BugReporterVisitor> Visitor = nullptr) const;

public:
  void checkPreStmt(const CXXMemberCallExpr *B, CheckerContext &C) const;
};
} // end anonymous namespace

static const Expr *getDenomExpr(const ExplodedNode *N) {
  const Stmt *S = N->getLocationAs<PreStmt>()->getStmt();
  if (const auto *BE = dyn_cast<BinaryOperator>(S))
    return BE->getRHS();
  return nullptr;
}

void DivZeroChecker::reportBug(
    const char *Msg, ProgramStateRef StateZero, CheckerContext &C,
    std::unique_ptr<BugReporterVisitor> Visitor) const {
  if (ExplodedNode *N = C.generateErrorNode(StateZero)) {
    if (!BT)
      BT.reset(new BuiltinBug(this, "Division by zero"));

    auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
    R->addVisitor(std::move(Visitor));
    bugreporter::trackExpressionValue(N, getDenomExpr(N), *R);
    C.emitReport(std::move(R));
  }
}

void DivZeroChecker::checkPreStmt(const CXXMemberCallExpr *E,
                                  CheckerContext &C) const {
  if (E->getBeginLoc().printToString(C.getSourceManager()).find("wf_simulator.cpp") == -1)
    return;
    
  cout << "DivZeroChecker::checkPreStmt" << E->getImplicitObjectArgument()->getStmtClassName();
  cout << " name: " << E->getMethodDecl()->getNameAsString();
  if (const auto *ME = dyn_cast<DeclRefExpr>(E->getImplicitObjectArgument()))
    cout << " DeclRefExpr:" << ME->getNameInfo().getAsString();
  if (const auto *ME = dyn_cast<MemberExpr>(E->getImplicitObjectArgument()))
    cout << " MemberExpr:" << ME->getMemberNameInfo().getAsString();
  if (const auto *ME = dyn_cast<ImplicitCastExpr>(E->getImplicitObjectArgument()))
    cout << " MemberExpr:" << ME->getCastKindName();
  cout << "(" << E->getBeginLoc().printToString(C.getSourceManager()) << ":" << E->getEndLoc().printToString(C.getSourceManager()) << ")";
  cout << "\n";
}

void ento::registerDivZeroChecker(CheckerManager &mgr) {
  mgr.registerChecker<DivZeroChecker>();
}

bool ento::shouldRegisterDivZeroChecker(const CheckerManager &mgr) {
  return true;
}
