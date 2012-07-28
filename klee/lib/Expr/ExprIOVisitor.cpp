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
#include <math.h>

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
			ref<Expr> lkid = ep.getKid(0);
			ref<Expr> rkid = ep.getKid(1);

				/**
				*	add by snowlxx  fwl
				*	两种实现方式
				**/
	    		/*第一种实现方法
				///无符号数处理
		    	ref<Expr> condu = klee::UltExpr::create(e, lkid);
				ref<Expr> zero = klee::ConstantExpr::create(0,e.get()->getWidth());
				
				///有符号数处理
				//生成表达式 ( l≥0 ) And ( r≥0 ) And ( e≤0 ) 
				ref<Expr> ls1 = klee::SgeExpr::create(lkid, zero);
				ref<Expr> rs1 = klee::SgeExpr::create(rkid, zero);
				ref<Expr> lrs1 = klee::AndExpr::create(ls1, rs1);
				ref<Expr> es1 = klee::SltExpr::create(e, zero);				
				ref<Expr> conds1 = klee::AndExpr::create(lrs1, es1);
				
				//生成表达式  ( l<0 ) And ( r<0 ) And ( e≥0 )
				ref<Expr> ls2 = klee::SltExpr::create(lkid, zero);
				ref<Expr> rs2 = klee::SltExpr::create(rkid, zero);
				ref<Expr> lrs2 = klee::AndExpr::create(ls2, rs2);
				ref<Expr> es2 = klee::SgeExpr::create(e, zero);				
				ref<Expr> conds2 = klee::AndExpr::create(lrs2, es2);
				
				//合并有符号的表达式  ( l≥0 ) And ( r≥0 ) And ( e≤0 ) OR ( l<0 ) And ( r<0 ) And ( e≥0 )
				ref<Expr> conds = klee::OrExpr::create(conds1, conds2);
				
				//合并有符号和无符号的表达式
				ref<Expr> cond = klee::OrExpr::create(condu, conds);
				*/
			
			
				//第二种实现方式：kint的判断方法
				///无符号的情况
				ref<Expr> condu = klee::UltExpr::create(e, lkid);
				ref<Expr> zero = klee::ConstantExpr::create(0,e.get()->getWidth());
				
				///有符号的情况：(((lhs + rhs) ^ lhs) & ((lhs + rhs) ^ rhs)) < 0)	直接判断符号位的变化
				ref<Expr> sxorl = klee::XorExpr::create(e, lkid);
				ref<Expr> sxorr = klee::XorExpr::create(e, rkid);
				ref<Expr> conds = klee::SltExpr::create(klee::AndExpr::create(sxorl, sxorr), zero);
				
				//组合表达式
				ref<Expr> cond  = klee::OrExpr::create(condu, conds);
				
				
				
				//可否分为两种情况来看，无符号加法生成的表达式和有符号加法生成的表达式组合（或的关系）成一个表达式，来判断是否发生溢出
				//关键是有符号的情况下如何判断溢出从而生成表达式？
				
				//ref<Expr> cond2 = klee::SltExpr::create();
		    	return cond;
	    	}
	    case Expr::Sub: res = visitSub(static_cast<SubExpr&>(ep)); 
		{
			ref<Expr> lkid = ep.getKid(0);
			ref<Expr> rkid = ep.getKid(1);
			ref<Expr> zero = klee::ConstantExpr::create(0,e.get()->getWidth());
			
			/**
			*	add by snowlxx fwl
			*	kint的实现方式
			**/
			//无符号判断方法
			ref<Expr> condu = klee::UltExpr::create(lkid, rkid);
			
			
			//有符号判断方法
			///kint判断方法:( ( (lhs - rhs) ^ lhs ) & (lhs ^ rhs) ) < 0
			///溢出的两种情况：1）正-负=负；2）负-正=正；
			///另外的两种情况：3）正-正=负，归类到无符号判断；4）负-负，不会溢出
			ref<Expr> elxor =klee::SubExpr::create(e, lkid);
			ref<Expr> lrxor =klee::XorExpr::create(lkid, rkid);
			ref<Expr> conds	=klee::SltExpr::create(klee::AndExpr::create(elxor, lrxor), zero);
			
			//组合表达式
			ref<Expr> cond  = klee::OrExpr::create(condu, conds);
			
			
			
			return cond;
		}
	    case Expr::Mul: res = visitMul(static_cast<MulExpr&>(ep));
		{
			ref<Expr> lkid = ep.getKid(0);
			ref<Expr> rkid = ep.getKid(1);
			
			
			
			/**
			*	add by snowlxx fwl
			*	
			**/
			
			//是不是需要判断rkid！=0，该判断在UDiv的实现中
			//ref<Expr> cond = klee::UltExpr::create(klee::UDivExpr::create(e, rkid), lkid);
			ref<Expr> condu = klee::UltExpr::create(klee::UDivExpr::create(e, rkid), lkid);
			
			//kint的判断条件:(s##n)(tmp >> n) != ((s##n)tmp) >> (n - 1)
			
			unsigned int wth = ep.getWidth()/2;
			//AShrExpr的左右kid都必须是Expr，width也必须保持一致
			ref<Expr> wthexpr = klee::ConstantExpr::create(wth,ep.getWidth());
			ref<Expr> wthexpr1 = klee::ConstantExpr::create(wth-1,wth);
			
			
			
			ref<Expr> eashr2n	= klee::ExtractExpr::create(klee::AShrExpr::create(e, wthexpr), 0, wth);
			
			ref<Expr> eashrn	= klee::AShrExpr::create(klee::ExtractExpr::create(e, 0, wth), wthexpr1);
			
			ref<Expr> conds		= klee::NeExpr::create(eashr2n, eashrn);
			
			//无符号和有符号结合
			ref<Expr> cond 		= klee::OrExpr::create(condu, conds);
					
			
			
			
			return cond; 
		}
	    case Expr::UDiv: res = visitUDiv(static_cast<UDivExpr&>(ep)); 
		{
			ref<Expr> rkid = ep.getKid(1);
			ref<Expr> cond = klee::EqExpr::create(rkid ,klee::ConstantExpr::create(0,ep.getWidth()));
			//ref<Expr> cond = klee::NeExpr::create(rkid ,klee::ConstantExpr::create(0,ep.getWidth()));
			return cond;
		}
		case Expr::SDiv: res = visitSDiv(static_cast<SDivExpr&>(ep));
		{
			ref<Expr> lkid = ep.getKid(0);
			ref<Expr> rkid = ep.getKid(1);
			ref<Expr> zero = klee::ConstantExpr::create(0,ep.getWidth());
			
			//这样来扩展-1是错误的
			//ref<Expr> neg1 = klee::ConstantExpr::create(-1,ep.getWidth());
			
			//ConstantExpr::create中，第一个数是无符号64位数
			ref<Expr> neg1 = klee::SubExpr::create(zero, klee::ConstantExpr::create(1,ep.getWidth()));
			
			/*
			//第一种实现方式
			//(rkid == 0) || ((lkid == e) &&(lkid !=0) && (rkid == -1))
			///(rkid == 0)
			ref<Expr> cond1 = klee::EqExpr::create(rkid, zero);
			
			
			///(rkid == -1)
			ref<Expr> req1	= klee::EqExpr::create(rkid, neg1);
			
			///(lkid == e)
			ref<Expr> leqe	= klee::EqExpr::create(lkid, e);
			///(lkid !=0) 
			ref<Expr> lneqz	= klee::NeExpr::create(lkid,zero);
			ref<Expr> lcond = klee::AndExpr::create(leqe, lneqz);
						
			ref<Expr> cond2 = klee::AndExpr::create(lcond, req1);//按位与和逻辑与，在此处应该是相同的
			
			ref<Expr> cond	= klee::OrExpr::create(cond1, cond2);//按位或和逻辑或，在此处是否相同？应该相同
			*/
			
			
			///*
			//第二种实现方式
			//(rhs == 0) || ((lhs == INT##n##_MIN) && (rhs == -1))
			//计算2的（n-1）次方,pow是double型，先强制转换成int型，然后转换成Expr
			ref<Expr> pown = klee::ConstantExpr::create((int)pow(2, (ep.getWidth()-1)), ep.getWidth());
			///是否等于负的2的（n-1）次方
			ref<Expr> leqn	= klee::EqExpr::create(lkid, klee::SubExpr::create(zero, pown));
			ref<Expr> req1	= klee::EqExpr::create(rkid, neg1);
			ref<Expr> cond2 = klee::AndExpr::create(leqn, req1);
			ref<Expr> cond1 = klee::EqExpr::create(rkid, zero);
			ref<Expr> cond	= klee::OrExpr::create(cond1,cond2);			
			
			//*/
			
			return cond;
		}
		
		case Expr::URem: res = visitURem(static_cast<URemExpr&>(ep)); 
		{
			ref<Expr> rkid = ep.getKid(1);
			ref<Expr> zero = klee::ConstantExpr::create(0,ep.getWidth());
			
			ref<Expr> cond = klee::EqExpr::create(zero, rkid);
			return cond;
		}
	    case Expr::SRem: res = visitSRem(static_cast<SRemExpr&>(ep)); 
		{
				ref<Expr> rkid = ep.getKid(1);
				ref<Expr> zero = klee::ConstantExpr::create(0,ep.getWidth());
				
				ref<Expr> cond = klee::EqExpr::create(zero, rkid);
				return cond;
		}
	    case Expr::Not: res = visitNot(static_cast<NotExpr&>(ep)); break;//应该不会发生溢出
	    case Expr::And: res = visitAnd(static_cast<AndExpr&>(ep)); break;//应该不会发生溢出
	    case Expr::Or: res = visitOr(static_cast<OrExpr&>(ep)); break;//应该不会发生溢出
	    case Expr::Xor: res = visitXor(static_cast<XorExpr&>(ep)); break;//应该不会发生溢出
	    case Expr::Shl: res = visitShl(static_cast<ShlExpr&>(ep));
		{
			ref<Expr> lkid = ep.getKid(0);
			ref<Expr> rkid = ep.getKid(1);

			//当一个操作数为常数（确切的说是和2的整数次方相近）时，Mul会自动优化为Shl，该Shl需要判断是否溢出
			ref<Expr> cond1 = klee::UltExpr::create(klee::LShrExpr::create(e, rkid), lkid);
			
			//1、gcc在编译程序时如果采用了优化选项，那么左移33位就会优化为左移1位，这里不考虑这种情况
			//2、目前的测试结果是，一旦rkid超出了width，s2e产生的条件表达式就直为空，那么下面的处理是否就不需要了？？？
			///原操作就是Shl的情况下，需要判断rkid>=Width的情况
			unsigned int z = ep.getWidth();
			ref<Expr> ewidth = klee::ConstantExpr::create(z, ep.getWidth());
			ref<Expr> cond2  = klee::UleExpr::create(ewidth, rkid);
			
			///合并条件表达式
			ref<Expr> cond = klee::OrExpr::create(cond1, cond2);
			
			return cond;
		}
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
	    case Expr::Constant: break;
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
