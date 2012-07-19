//===-- ExprIOVisitor.cpp ---------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Expr.h"
#include "klee/util/ExprIOVisitor.h"//Int Overflow

#include "llvm/Support/CommandLine.h"

#include <iostream>

namespace {
  llvm::cl::opt<bool>
  UseVisitorHash("use-visitor-hash", 
                 llvm::cl::desc("Use hash-consing during expr visitation."),
                 llvm::cl::init(true));
}

using namespace klee;
//这里存在一个Hash表，这个Hash表当中存放了什么呢？
ref<Expr> ExprIOVisitor::visit(const ref<Expr> &e) {
  if (!UseVisitorHash || isa<ConstantExpr>(e)) {
    return visitActual(e);
  } else {
    visited_ty::iterator it = visited.find(e);

    if (it!=visited.end()) {
      return it->second;
    } else {
      ref<Expr> res = visitActual(e);//肯定是在这里面实施实质性的操作
      visited.insert(std::make_pair(e, res));
      return res;
    }
  }
}

/*
 * 函数功能：这里只访问最外面一层的操作数；
 * 当我们只检测调用malloc时，这里的整数溢出漏洞会不会触发，这个时候，就只检测最外面一层的操作；
 *
 * */
ref<Expr> ExprIOVisitor::visitOutsideOp(const ref<Expr> &e) {
	  if (isa<ConstantExpr>(e)) {
	    return e;
	  } else {
	    Expr &ep = *e.get();

	    Action res = visitExpr(ep);


	    switch(ep.getKind()) {
	    case Expr::NotOptimized: res = visitNotOptimized(static_cast<NotOptimizedExpr&>(ep)); break;
	    case Expr::Read: res = visitRead(static_cast<ReadExpr&>(ep)); break;
	    case Expr::Select: res = visitSelect(static_cast<SelectExpr&>(ep)); break;
	    case Expr::Concat: res = visitConcat(static_cast<ConcatExpr&>(ep)); break;
	    case Expr::Extract: res = visitExtract(static_cast<ExtractExpr&>(ep)); break;
	    case Expr::ZExt: res = visitZExt(static_cast<ZExtExpr&>(ep)); break;
	    case Expr::SExt: res = visitSExt(static_cast<SExtExpr&>(ep)); break;

	    //这里先以此为类子，Add w32 a b ---> UltExpr w32 (Add w32 a b) (w32 a)
	    case Expr::Add: res = visitAdd(static_cast<AddExpr&>(ep));
	    	{
	    		std::cout << "res.argument" << res.argument << '\n';
			ref<Expr> lkid = ep.getKid(0);
	    		ref<Expr> rkid = ep.getKid(1);
	    		//int j = 0;

	    		std::cout << "e->Width:" << e.get()->getWidth() << '\n';/////这里Width还是不能使用

		    	if ( ep.getWidth() == ep.Int32)
		    	{
		    		ref<Expr> cond = klee::UltExpr::create(e, lkid);
		    		return cond;
		    	}
		    	else
		    	{

		    	}
	    		break;
	    	}
	    	//取得l，r
//	    	ref<Expr> lkid = ep.getKid(0);
//
//	    	ref<Expr> rkid = ep.getKid(1);

	    	//判断是不是32位的
	    case Expr::Sub: res = visitSub(static_cast<SubExpr&>(ep)); break;
	    case Expr::Mul: res = visitMul(static_cast<MulExpr&>(ep));
		{
			ref<Expr> lkid = ep.getKid(0);
			ref<Expr> rkid = ep.getKid(1);
			
			if ( ep.getWidth() == ep.Int32 ){
				ref<Expr> cond = klee::UltExpr::create(klee::UDivExpr::create(e,rkid),lkid);
				return cond; 
			}
		 break;
		}
	    case Expr::UDiv: res = visitUDiv(static_cast<UDivExpr&>(ep)); break;
	    case Expr::SDiv: res = visitSDiv(static_cast<SDivExpr&>(ep)); break;
	    case Expr::URem: res = visitURem(static_cast<URemExpr&>(ep)); break;
	    case Expr::SRem: res = visitSRem(static_cast<SRemExpr&>(ep)); break;
	    case Expr::Not: res = visitNot(static_cast<NotExpr&>(ep)); break;
	    case Expr::And: res = visitAnd(static_cast<AndExpr&>(ep)); break;
	    case Expr::Or: res = visitOr(static_cast<OrExpr&>(ep)); break;
	    case Expr::Xor: res = visitXor(static_cast<XorExpr&>(ep)); break;
	    case Expr::Shl: res = visitShl(static_cast<ShlExpr&>(ep)); break;
	    case Expr::LShr: res = visitLShr(static_cast<LShrExpr&>(ep)); break;
	    case Expr::AShr: res = visitAShr(static_cast<AShrExpr&>(ep)); break;
	    case Expr::Eq: res = visitEq(static_cast<EqExpr&>(ep)); break;
	    case Expr::Ne: res = visitNe(static_cast<NeExpr&>(ep)); break;
	    case Expr::Ult: res = visitUlt(static_cast<UltExpr&>(ep)); break;
	    case Expr::Ule: res = visitUle(static_cast<UleExpr&>(ep)); break;
	    case Expr::Ugt: res = visitUgt(static_cast<UgtExpr&>(ep)); break;
	    case Expr::Uge: res = visitUge(static_cast<UgeExpr&>(ep)); break;
	    case Expr::Slt: res = visitSlt(static_cast<SltExpr&>(ep)); break;
	    case Expr::Sle: res = visitSle(static_cast<SleExpr&>(ep)); break;
	    case Expr::Sgt: res = visitSgt(static_cast<SgtExpr&>(ep)); break;
	    case Expr::Sge: res = visitSge(static_cast<SgeExpr&>(ep)); break;
	    case Expr::Constant:
	    default:
	      assert(0 && "invalid expression kind");
	    }//switch
	  }//else
	return e;
}

ref<Expr> ExprIOVisitor::visitActual(const ref<Expr> &e) {
  if (isa<ConstantExpr>(e)) {    
    return e;
  } else {
    Expr &ep = *e.get();

    Action res = visitExpr(ep);
    switch(res.kind) {
    case Action::DoChildren:
      // continue with normal action
      break;
    case Action::SkipChildren:
      return e;
    case Action::ChangeTo:
      return res.argument;
    }

    switch(ep.getKind()) {
    case Expr::NotOptimized: res = visitNotOptimized(static_cast<NotOptimizedExpr&>(ep)); break;
    case Expr::Read: res = visitRead(static_cast<ReadExpr&>(ep)); break;
    case Expr::Select: res = visitSelect(static_cast<SelectExpr&>(ep)); break;
    case Expr::Concat: res = visitConcat(static_cast<ConcatExpr&>(ep)); break;
    case Expr::Extract: res = visitExtract(static_cast<ExtractExpr&>(ep)); break;
    case Expr::ZExt: res = visitZExt(static_cast<ZExtExpr&>(ep)); break;
    case Expr::SExt: res = visitSExt(static_cast<SExtExpr&>(ep)); break;
    case Expr::Add: res = visitAdd(static_cast<AddExpr&>(ep)); break;
    case Expr::Sub: res = visitSub(static_cast<SubExpr&>(ep)); break;
    case Expr::Mul: res = visitMul(static_cast<MulExpr&>(ep)); break;
    case Expr::UDiv: res = visitUDiv(static_cast<UDivExpr&>(ep)); break;
    case Expr::SDiv: res = visitSDiv(static_cast<SDivExpr&>(ep)); break;
    case Expr::URem: res = visitURem(static_cast<URemExpr&>(ep)); break;
    case Expr::SRem: res = visitSRem(static_cast<SRemExpr&>(ep)); break;
    case Expr::Not: res = visitNot(static_cast<NotExpr&>(ep)); break;
    case Expr::And: res = visitAnd(static_cast<AndExpr&>(ep)); break;
    case Expr::Or: res = visitOr(static_cast<OrExpr&>(ep)); break;
    case Expr::Xor: res = visitXor(static_cast<XorExpr&>(ep)); break;
    case Expr::Shl: res = visitShl(static_cast<ShlExpr&>(ep)); break;
    case Expr::LShr: res = visitLShr(static_cast<LShrExpr&>(ep)); break;
    case Expr::AShr: res = visitAShr(static_cast<AShrExpr&>(ep)); break;
    case Expr::Eq: res = visitEq(static_cast<EqExpr&>(ep)); break;
    case Expr::Ne: res = visitNe(static_cast<NeExpr&>(ep)); break;
    case Expr::Ult: res = visitUlt(static_cast<UltExpr&>(ep)); break;
    case Expr::Ule: res = visitUle(static_cast<UleExpr&>(ep)); break;
    case Expr::Ugt: res = visitUgt(static_cast<UgtExpr&>(ep)); break;
    case Expr::Uge: res = visitUge(static_cast<UgeExpr&>(ep)); break;
    case Expr::Slt: res = visitSlt(static_cast<SltExpr&>(ep)); break;
    case Expr::Sle: res = visitSle(static_cast<SleExpr&>(ep)); break;
    case Expr::Sgt: res = visitSgt(static_cast<SgtExpr&>(ep)); break;
    case Expr::Sge: res = visitSge(static_cast<SgeExpr&>(ep)); break;
    case Expr::Constant:
    default:
      assert(0 && "invalid expression kind");
    }

    switch(res.kind) {
    default:
      assert(0 && "invalid kind");
    case Action::DoChildren: {  
      bool rebuild = false;
      ref<Expr> e(&ep), kids[8];
      unsigned count = ep.getNumKids();
      for (unsigned i=0; i<count; i++) {
        ref<Expr> kid = ep.getKid(i);
        kids[i] = visit(kid);
        if (kids[i] != kid)
          rebuild = true;
      }
      if (rebuild) {
        e = ep.rebuild(kids);
        if (recursive)
          e = visit(e);
      }
      if (!isa<ConstantExpr>(e)) {
        res = visitExprPost(*e.get());
        if (res.kind==Action::ChangeTo)
          e = res.argument;
      }
      return e;
    }
    case Action::SkipChildren:
      return e;
    case Action::ChangeTo:
      return res.argument;
    }
  }
}

ExprIOVisitor::Action ExprIOVisitor::visitExpr(const Expr&) {
  return Action::doChildren();
}

ExprIOVisitor::Action ExprIOVisitor::visitExprPost(const Expr&) {
  return Action::skipChildren();
}

ExprIOVisitor::Action ExprIOVisitor::visitNotOptimized(const NotOptimizedExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitRead(const ReadExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitSelect(const SelectExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitConcat(const ConcatExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitExtract(const ExtractExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitZExt(const ZExtExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitSExt(const SExtExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitAdd(const AddExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitSub(const SubExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitMul(const MulExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitUDiv(const UDivExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitSDiv(const SDivExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitURem(const URemExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitSRem(const SRemExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitNot(const NotExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitAnd(const AndExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitOr(const OrExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitXor(const XorExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitShl(const ShlExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitLShr(const LShrExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitAShr(const AShrExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitEq(const EqExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitNe(const NeExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitUlt(const UltExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitUle(const UleExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitUgt(const UgtExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitUge(const UgeExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitSlt(const SltExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitSle(const SleExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitSgt(const SgtExpr&) {
  return Action::doChildren(); 
}

ExprIOVisitor::Action ExprIOVisitor::visitSge(const SgeExpr&) {
  return Action::doChildren(); 
}

