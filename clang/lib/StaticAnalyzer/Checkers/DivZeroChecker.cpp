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
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include <iostream>
#include <map>

using namespace std;
using namespace clang;
using namespace ento;
using namespace ento::nonloc;
using namespace taint;

namespace {
class DivZeroChecker : public Checker< check::PreStmt<CXXMemberCallExpr>, check::PostStmt<CXXConstructExpr>> {
  mutable std::unique_ptr<BuiltinBug> BT;
  void reportBug(const char *Msg, ProgramStateRef StateZero, CheckerContext &C,
                 std::unique_ptr<BugReporterVisitor> Visitor = nullptr) const;

public:
  void checkPreStmt(const CXXMemberCallExpr *B, CheckerContext &C) const;
  void checkPostStmt(const CXXConstructExpr *E,
                                  CheckerContext &C) const;

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
REGISTER_MAP_WITH_PROGRAMSTATE(RateFrequency, int, int)

void DivZeroChecker::checkPostStmt(const CXXConstructExpr *constructor,
                                  CheckerContext &C) const {
    for(auto arg: constructor->arguments()) {
      //Denom.getAsSymbolicExpression()->
      if (const auto *ic = dyn_cast<ImplicitCastExpr>(arg)) {
        SVal Denom = C.getSVal(ic->getSubExpr());
        if (constructor->getConstructor()->getNameAsString() != "Rate")
          return;
        cout << "checkPostStmt: ";

        cout << " constructor args: ";
        cout << " arg " << ic->getSubExpr()->getStmtClassName() << " isUnknownOrUndef(): " << Denom.isUnknownOrUndef();
        cout << " isConstant(): " << Denom.isConstant();

        Optional<ConcreteInt> i = Denom.getAs<ConcreteInt>();
        if (i) {
          
          cout << " getExtValue: " << i->getValue().getExtValue();
          int key = constructor->getID(C.getASTContext());
          cout << " getID: " << key;
          int value = i->getValue().getExtValue();
          ProgramStateRef state = C.getState()->set<RateFrequency>(key, value);
          C.addTransition(state);
          //const int* result = state->get<RateFrequency>(key);
          //cout << " state: " << *result;

        }
        cout << " (" << constructor->getBeginLoc().printToString(C.getSourceManager()) << ":" << constructor->getEndLoc().printToString(C.getSourceManager()) << ")";
        cout << "\n";

      }
    }
}

void DivZeroChecker::checkPreStmt(const CXXMemberCallExpr *E,
                                  CheckerContext &C) const {
  if (E->getBeginLoc().printToString(C.getSourceManager()).find("wf_simulator.cpp") == -1)
    return;

  
  cout << "DivZeroChecker::checkPreStmt" << E->getImplicitObjectArgument()->getStmtClassName();
  cout << " name: " << E->getMethodDecl()->getNameAsString();
    
  if (const auto *ME = dyn_cast<MemberExpr>(E->getImplicitObjectArgument())) {
    cout << " MemberExpr: " << ME->getMemberNameInfo().getAsString();
  }
  const DeclRefExpr* declRef ;
  if (const auto *ME = dyn_cast<ImplicitCastExpr>(E->getImplicitObjectArgument())) {
    cout << " ImplicitCastExpr: " << ME->getSubExpr()->getStmtClassName();
    if (const auto *SE = dyn_cast<DeclRefExpr>(ME->getSubExpr())) {
      cout << " DeclRefExpr: " << SE->getDecl()->getNameAsString();
      declRef  = SE;
    }
  } 
  else if (const auto *ME = dyn_cast<DeclRefExpr>(E->getImplicitObjectArgument())) {
    cout << " DeclRefExpr: " << ME->getNameInfo().getAsString();
    declRef  = ME;
  }
  if (declRef  && declRef->getDecl()) {
    //declRef->getDecl()->dump();
    const_cast<DeclRefExpr*>(declRef->getDecl())->dump();
    /*if (auto *vd = dyn_cast<VarDecl>(decl->getDecl())) {
      const_cast<VarDecl*>(vd)->dump();
      /*if (const_cast<VarDecl*>(vd)->hasInit()) {
        if (const auto *constructor = dyn_cast<CXXConstructExpr>(vd->getInit())) {
          int key = constructor->getID(C.getASTContext());
          cout << " getID: " << key;
          ProgramStateRef state = C.getState();
          if(const int* result = state->get<RateFrequency>(key)) {
            int r = *result;
            cout << " getValue: " << r;
          } else {
            cout << " getValue: ERROR";
          }
        }
      }
    }*/
  }
  cout << " (" << E->getBeginLoc().printToString(C.getSourceManager()) << ":" << E->getEndLoc().printToString(C.getSourceManager()) << ")";
  cout << "\n";
}

void ento::registerDivZeroChecker(CheckerManager &mgr) {
  mgr.registerChecker<DivZeroChecker>();
}

bool ento::shouldRegisterDivZeroChecker(const CheckerManager &mgr) {
  return true;
}
