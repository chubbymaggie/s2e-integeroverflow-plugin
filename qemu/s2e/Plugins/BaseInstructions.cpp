/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in S2E-AUTHORS file.
 *
 */

extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#ifdef CONFIG_WIN32
#include <windows.h>
#endif

#include "BaseInstructions.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>
#include <sstream>

#include <list>

#include <llvm/Support/TimeValue.h>
#include <klee/Searcher.h>
#include <klee/Solver.h>
#include <klee/util/ExprIOVisitor.h>

namespace s2e {
namespace plugins {

using namespace std;
using namespace klee;

S2E_DEFINE_PLUGIN(BaseInstructions, "Default set of custom instructions plugin", "",);

void BaseInstructions::initialize()
{
    s2e()->getCorePlugin()->onCustomInstruction.connect(
            sigc::mem_fun(*this, &BaseInstructions::onCustomInstruction));

}

void BaseInstructions::makeSymbolic(S2EExecutionState *state, bool makeConcolic)
{
    uint32_t address, size, name; // XXX
    bool ok = true;
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                         &address, 4);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                         &size, 4);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                         &name, 4);

    if(!ok) {
        s2e()->getWarningsStream(state)
            << "ERROR: symbolic argument was passed to s2e_op "
               " insert_symbolic opcode\n";
        return;
    }

    std::string nameStr = "unnamed";
    if(name && !state->readString(name, nameStr)) {
        s2e()->getWarningsStream(state)
                << "Error reading string from the guest\n";
    }

    s2e()->getMessagesStream(state)
            << "Inserting symbolic data at " << hexval(address)
            << " of size " << hexval(size)
            << " with name '" << nameStr << "'\n";

    std::vector<unsigned char> concreteData;
    vector<ref<Expr> > symb;

    if (makeConcolic) {
        for (unsigned i = 0; i< size; ++i) {
            uint8_t byte = 0;
            if (!state->readMemoryConcrete8(address + i, &byte)) {
                s2e()->getWarningsStream(state)
                    << "Can not concretize/read symbolic value"
                    << " at " << hexval(address + i) << ". System state not modified.\n";
                return;
            }
            concreteData.push_back(byte);
        }
        symb = state->createConcolicArray(nameStr, size, concreteData);
    } else {
        symb = state->createSymbolicArray(nameStr, size);
    }


    for(unsigned i = 0; i < size; ++i) {
        if(!state->writeMemory8(address + i, symb[i])) {
            s2e()->getWarningsStream(state)
                << "Can not insert symbolic value"
                << " at " << hexval(address + i)
                << ": can not write to memory\n";
        }
    }
}

void BaseInstructions::isSymbolic(S2EExecutionState *state)
{
    uint32_t address;
    uint32_t result;
    char buf;
    bool ok = true;
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                         &address, 4);

    if(!ok) {
        s2e()->getWarningsStream(state)
            << "ERROR: symbolic argument was passed to s2e_op is_symbolic\n";
        return;
    }

    s2e()->getMessagesStream(state)
            << "Testing whether data at " << hexval(address)
            << " is symbolic:";

    // readMemoryConcrete fails if the value is symbolic
    result = !state->readMemoryConcrete(address, &buf, 1);
    s2e()->getMessagesStream(state)
            << (result ? " true" : " false") << '\n';
    state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &result, 4);
}

void BaseInstructions::killState(S2EExecutionState *state)
{
    std::string message;
    uint32_t messagePtr;
    bool ok = true;
    klee::ref<klee::Expr> status = state->readCpuRegister(CPU_OFFSET(regs[R_EAX]), klee::Expr::Int32);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &messagePtr, 4);

    if (!ok) {
        s2e()->getWarningsStream(state)
            << "ERROR: symbolic argument was passed to s2e_kill_state \n";
    } else {
        message="<NO MESSAGE>";
        if(messagePtr && !state->readString(messagePtr, message)) {
            s2e()->getWarningsStream(state)
                << "Error reading message string from the guest\n";
        }
    }

    //Kill the current state
    s2e()->getMessagesStream(state) << "Killing state "  << state->getID() << '\n';
    std::ostringstream os;
    os << "State was terminated by opcode\n"
       << "            message: \"" << message << "\"\n"
       << "            status: " << status;
    s2e()->getExecutor()->terminateStateEarly(*state, os.str());
}

void BaseInstructions::printExpression(S2EExecutionState *state)
{
    //Print the expression
    uint32_t name; //xxx
    bool ok = true;
    ref<Expr> val = state->readCpuRegister(offsetof(CPUX86State, regs[R_EAX]), klee::Expr::Int32);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                         &name, 4);

    if(!ok) {
        s2e()->getWarningsStream(state)
            << "ERROR: symbolic argument was passed to s2e_op "
               "print_expression opcode\n";
        return;
    }

    std::string nameStr = "<NO NAME>";
    if(name && !state->readString(name, nameStr)) {
        s2e()->getWarningsStream(state)
                << "Error reading string from the guest\n";
    }


    s2e()->getMessagesStream() << "SymbExpression " << nameStr << " - "
                               <<val << '\n';
}

void BaseInstructions::printMemory(S2EExecutionState *state)
{
    uint32_t address, size, name; // XXX should account for 64 bits archs
    bool ok = true;
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                         &address, 4);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                         &size, 4);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                         &name, 4);

    if(!ok) {
        s2e()->getWarningsStream(state)
            << "ERROR: symbolic argument was passed to s2e_op "
               "print_expression opcode\n";
        return;
    }

    std::string nameStr = "<NO NAME>";
    if(name && !state->readString(name, nameStr)) {
        s2e()->getWarningsStream(state)
                << "Error reading string from the guest\n";
    }

    s2e()->getMessagesStream() << "Symbolic memory dump of " << nameStr << '\n';

    for (uint32_t i=0; i<size; ++i) {

        s2e()->getMessagesStream() << hexval(address+i) << ": ";
        ref<Expr> res = state->readMemory8(address+i);
        if (res.isNull()) {
            s2e()->getMessagesStream() << "Invalid pointer\n";
        }else {
            s2e()->getMessagesStream() << res << '\n';
        }
    }
}


void BaseInstructions::concretize(S2EExecutionState *state, bool addConstraint)
{
    uint32_t address, size;

    bool ok = true;
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                         &address, 4);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                         &size, 4);

    if(!ok) {
        s2e()->getWarningsStream(state)
            << "ERROR: symbolic argument was passed to s2e_op "
               " get_example opcode\n";
        return;
    }

    for(unsigned i = 0; i < size; ++i) {
        if (!state->readMemoryConcrete8(address + i, NULL, S2EExecutionState::VirtualAddress, addConstraint)) {
            s2e()->getWarningsStream(state)
                << "Can not concretize memory"
                << " at " << hexval(address + i) << '\n';
        }
    }
}


/**
 *
 * 作者：吴志勇
 * 更新时间：20120705
 * 该函数主要是把一个符号表达式转换成符合计算整数溢出检验的符号表达式
 * 目前功能：当前只要对一个32位的，加法的，无需递归的函数进行修改；
 * 需要改进的地方：很多；
 *
 * */
/*klee::ref<klee::Expr> CExprForIntOF(klee::ref<klee::Expr> &e)
{
	//这里只是生成了一个指针，肯定是需要申请一个新的空间，在这个基础之上，再进行相关的操作
	klee::ref<klee::Expr> ge;

	//这里应该是根据e的类型，再进行相关的操作
	switch (e->getKind()) {
//	  case Expr::Constant:
//	    return T(cast<ConstantExpr>(e));
//
//	  case Expr::NotOptimized:
//	    break;
//
//	  case Expr::Read: {
//	    const ReadExpr *re = cast<ReadExpr>(e);
//	    T index = evaluate(re->index);
//
//	    assert(re->getWidth()==Expr::Int8 && "unexpected multibyte read");
//
//	    return evalRead(re->updates, index);
//	  }
//
//	  case Expr::Select: {
//	    const SelectExpr *se = cast<SelectExpr>(e);
//	    T cond = evaluate(se->cond);
//
//	    if (cond.mustEqual(1)) {
//	      return evaluate(se->trueExpr);
//	    } else if (cond.mustEqual(0)) {
//	      return evaluate(se->falseExpr);
//	    } else {
//	      return evaluate(se->trueExpr).set_union(evaluate(se->falseExpr));
//	    }
//	  }
//
//	    // XXX these should be unrolled to ensure nice inline
//	  case Expr::Concat: {
//	    const Expr *ep = e.get();
//	    T res(0);
//	    for (unsigned i=0; i<ep->getNumKids(); i++)
//	      res = res.concat(evaluate(ep->getKid(i)),8);
//	    return res;
//	  }

	    // Arithmetic

//	  case Expr::Add: {
//	    //问题：如何取得Add的类型？
//		if (e->getWidth() == 8)//问题：这里的宽度有是8的么？
//		{
//
//		}
//		else if(e->getWidth() == 16)
//		{
//
//		}
//		else if(e->getWidth() == 32)
//		{
//			//这里可以取得left，再取得right，再进行相关的比较
//			//在不考虑递归的情况下，这里创建一个新的ge应该不会错；
//			klee::ref<klee::Expr> left, right;
//		    const BinaryExpr *be = cast<BinaryExpr>(e);
//			left = be->left;
//			right = be->right;
//
//			ge = klee::AddExpr::create( klee::Expr::Int64, &left, &right);
//			//问题：这里的有符号数和无符号数会对Int64发生影响么？有没有必要换成其它的呢？没有必要，64位就行。
//
//
//		}
//		else if(e->getWidth() == 64)
//		{
//
//		}
//		else
//
//
//		const BinaryExpr *be = cast<BinaryExpr>(e);
//	    unsigned width = be->left->getWidth();
//	    return evaluate(be->left).add(evaluate(be->right), width);
//	  }
//	  case Expr::Sub: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    unsigned width = be->left->getWidth();
//	    return evaluate(be->left).sub(evaluate(be->right), width);
//	  }
//	  case Expr::Mul: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    unsigned width = be->left->getWidth();
//	    return evaluate(be->left).mul(evaluate(be->right), width);
//	  }
//	  case Expr::UDiv: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    unsigned width = be->left->getWidth();
//	    return evaluate(be->left).udiv(evaluate(be->right), width);
//	  }
//	  case Expr::SDiv: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    unsigned width = be->left->getWidth();
//	    return evaluate(be->left).sdiv(evaluate(be->right), width);
//	  }
//	  case Expr::URem: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    unsigned width = be->left->getWidth();
//	    return evaluate(be->left).urem(evaluate(be->right), width);
//	  }
//	  case Expr::SRem: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    unsigned width = be->left->getWidth();
//	    return evaluate(be->left).srem(evaluate(be->right), width);
//	  }
//
//	    // Binary
//
//	  case Expr::And: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    return evaluate(be->left).binaryAnd(evaluate(be->right));
//	  }
//	  case Expr::Or: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    return evaluate(be->left).binaryOr(evaluate(be->right));
//	  }
//	  case Expr::Xor: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    return evaluate(be->left).binaryXor(evaluate(be->right));
//	  }
//	  case Expr::Shl: {
//	    //    BinaryExpr *be = cast<BinaryExpr>(e);
//	    //    unsigned width = be->left->getWidth();
//	    //    return evaluate(be->left).shl(evaluate(be->right), width);
//	    break;
//	  }
//	  case Expr::LShr: {
//	    //    BinaryExpr *be = cast<BinaryExpr>(e);
//	    //    unsigned width = be->left->getWidth();
//	    //    return evaluate(be->left).lshr(evaluate(be->right), width);
//	    break;
//	  }
//	  case Expr::AShr: {
//	    //    BinaryExpr *be = cast<BinaryExpr>(e);
//	    //    unsigned width = be->left->getWidth();
//	    //    return evaluate(be->left).ashr(evaluate(be->right), width);
//	    break;
//	  }
//
//	    // Comparison
//
//	  case Expr::Eq: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    T left = evaluate(be->left);
//	    T right = evaluate(be->right);
//
//	    if (left.mustEqual(right)) {
//	      return T(1);
//	    } else if (!left.mayEqual(right)) {
//	      return T(0);
//	    }
//	    break;
//	  }
//
//	  case Expr::Ult: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    T left = evaluate(be->left);
//	    T right = evaluate(be->right);
//
//	    if (left.max() < right.min()) {
//	      return T(1);
//	    } else if (left.min() >= right.max()) {
//	      return T(0);
//	    }
//	    break;
//	  }
//	  case Expr::Ule: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    T left = evaluate(be->left);
//	    T right = evaluate(be->right);
//
//	    if (left.max() <= right.min()) {
//	      return T(1);
//	    } else if (left.min() > right.max()) {
//	      return T(0);
//	    }
//	    break;
//	  }
//	  case Expr::Slt: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    T left = evaluate(be->left);
//	    T right = evaluate(be->right);
//	    unsigned bits = be->left->getWidth();
//
//	    if (left.maxSigned(bits) < right.minSigned(bits)) {
//	      return T(1);
//	    } else if (left.minSigned(bits) >= right.maxSigned(bits)) {
//	      return T(0);
//	    }
//	    break;
//	  }
//	  case Expr::Sle: {
//	    const BinaryExpr *be = cast<BinaryExpr>(e);
//	    T left = evaluate(be->left);
//	    T right = evaluate(be->right);
//	    unsigned bits = be->left->getWidth();
//
//	    if (left.maxSigned(bits) <= right.minSigned(bits)) {
//	      return T(1);
//	    } else if (left.minSigned(bits) > right.maxSigned(bits)) {
//	      return T(0);
//	    }
//	    break;
//	  }
//
//	  case Expr::Ne:
//	  case Expr::Ugt:
//	  case Expr::Uge:
//	  case Expr::Sgt:
//	  case Expr::Sge:
//	    assert(0 && "invalid expressions (uncanonicalized)");

	  default:
	    break;
	}


	ge = e;
	return ge;
}
*/

/**
 *
 * 作者：吴志勇
 * 更新时间：20120703
 * 该函数主要是用来获取整数溢出的例子.
 * 目前功能：判断有没有发生整数溢出；
 * 需要改进的地方：当前这里还只是对其中32位的int类型的进行相关的检测；
 *
 * */

void BaseInstructions::getIntOverflowExample(S2EExecutionState *state)
{
    	uint32_t address, size;
	bool ok = true;
    
	ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                         &address, 4);
    	ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                         &size, 4);

    	if(!ok) {
        	s2e()->getWarningsStream(state)
            		<< "ERROR: symbolic argument was passed to s2e_op "
               		" getIntOverflowExample opcode" << '\n';
        	return;
    	}

    //需要在这里建立多种断言


    //需要改进：当前，这里默认size的值就是Int32位的；
    	//klee::ref<klee::Expr> symValue = state->readMemory(address, klee::Expr::Int16);
		//test
    	klee::ref<klee::Expr> symValue = state->readMemory(address, klee::Expr::Int32);
/*	s2e()->getMessagesStream() << "---------param1 symbolic value : " << symValue << '\n';

	klee::ref<klee::Expr> symValue_1 = klee::ZExtExpr::create(symValue, klee::Expr::Int64);
	klee::ref<klee::Expr> symValue_2 = klee::SExtExpr::create(symValue, klee::Expr::Int64);

	// klee::ref<klee::Expr> cond = klee::EqExpr::create(symValue, klee::ConstantExpr::create(0x8, symValue.get()->getWidth()));
	klee::ref<klee::Expr> cond_1 = klee::UgtExpr::create(symValue_1, klee::ConstantExpr::create(0xfffffffe, klee::Expr::Int64));
	klee::ref<klee::Expr> cond_2 = klee::SgtExpr::create(symValue_2, klee::ConstantExpr::create(0x7fffffff, klee::Expr::Int64));
	//klee::ref<klee::Expr> cond = klee::EqExpr::create(klee::OrExpr::create(cond_1, cond_2), klee::ConstantExpr::create(0x1, klee::Expr::Bool));
	s2e()->getMessagesStream() << "---------assert cond : " << cond_1 << '\n';
*/
	//打算这里对表达式进行重写

	s2e()->getMessagesStream() << "symValue:" << symValue << '\n';

	ExprIOVisitor e;
	list < klee::ref<klee::Expr> > res;
	klee::ref<klee::Expr> current,overflow;//current是当前处理的结点，overflow是重构后的条件。 by fwl
	bool isTrue;

	res.push_back(symValue);

	while (!res.empty()){
		current = res.front();
		s2e()->getMessagesStream() << "######current:" << current << '\n';
		res.pop_front();
		overflow = e.visitOutsideOp(current);
		
		s2e()->getMessagesStream() << "######overflow:" << overflow << '\n';
		//s2e()->getMessagesStream() << "######overflowKind:" << overflow.get()->getKind() << '\n';
		if ((overflow.get()->getKind() == klee::Expr::Read))/*||
				(overflow.get()->getKind() == klee::Expr::ReadLSB)||
				(overflow.get()->getKind() == klee::Expr::ReadMSB))*/
			continue;
		if (overflow.get()->getWidth() == klee::Expr::Bool){
			if (!(s2e()->getExecutor()->getSolver()->mayBeTrue(klee::Query(state->constraints, overflow), isTrue))) {
				s2e()->getWarningsStream() << "Failed to assert the condition!!" << '\n';
			}
			if (isTrue){
				ConcreteInputs inputs;
				ConcreteInputs::iterator it;

				//首先，把原来的constraints保存一下；
				ConstraintManager constraints_before(state->constraints);
				ConstraintManager * p_constraints;
				p_constraints = &state->constraints;

				s2e()->getExecutor()->addConstraint(*state, overflow);//这里可以把约束条件添加进来么？

				std::string constraint_str;

				//s2e()->getExecutor()->getConstraintLog( *state, constraint_str, false);
				//s2e()->getMessagesStream() << "constraint_str: " << constraint_str.c_str() << " : ";

				s2e()->getExecutor()->getSymbolicSolution(*state, inputs);
				s2e()->getMessagesStream()  << "---------malloc crash detected!" << '\n'
											<< "---------input value : " << '\n';
				for (it = inputs.begin(); it != inputs.end(); ++it) {
					const VarValuePair &vp = *it;
					s2e()->getMessagesStream() 	<< "---------" << vp.first << " : ";

					for (unsigned i=0; i<vp.second.size(); ++i) {
					
						s2e()->getMessagesStream() << hexval((unsigned char) vp.second[i]) << " ";
					}
					s2e()->getMessagesStream() << '\n';
				}

				//其次，等计算完了之后，再把相关的条件恢复过来，即可。
				state->constraints = constraints_before;

				//这里还需要把原来的constraints清空，这里是不是应该删除阿？
				p_constraints->empty();
				//delete p_constraints; //error!

				//s2e()->getExecutor()->getConstraintLog( *state, constraint_str, false);
				//s2e()->getMessagesStream() << "state.constraints: " << constraint_str.c_str() << " : ";
				break;	
			}
		}
		for (int i = 0;i != current->getNumKids(); ++i){
			res.push_back(current->getKid(i));			
		}
	}
}



void BaseInstructions::sleep(S2EExecutionState *state)
{
    uint32_t duration = 0;
    state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &duration, sizeof(uint32_t));
    s2e()->getDebugStream() << "Sleeping " << duration << " seconds\n";

    llvm::sys::TimeValue startTime = llvm::sys::TimeValue::now();

    while (llvm::sys::TimeValue::now().seconds() - startTime.seconds() < duration) {
        #ifdef _WIN32
        Sleep(1000);
        #else
        ::sleep(1);
        #endif
    }
}

void BaseInstructions::printMessage(S2EExecutionState *state, bool isWarning)
{
    uint32_t address = 0; //XXX
    bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                                &address, 4);
    if(!ok) {
        s2e()->getWarningsStream(state)
            << "ERROR: symbolic argument was passed to s2e_op "
               " message opcode\n";
        return;
    }

    std::string str="";
    if(!address || !state->readString(address, str)) {
        s2e()->getWarningsStream(state)
                << "Error reading string message from the guest at address "
                << hexval(address) << '\n';
    } else {
        llvm::raw_ostream *stream;
        if(isWarning)
            stream = &s2e()->getWarningsStream(state);
        else
            stream = &s2e()->getMessagesStream(state);
        (*stream) << "Message from guest (" << hexval(address) <<
                     "): " <<  str << '\n';
    }
}

void BaseInstructions::invokePlugin(S2EExecutionState *state)
{
    BaseInstructionsPluginInvokerInterface *iface = NULL;
    Plugin *plugin;
    std::string pluginName;
    uint32_t pluginNamePointer = 0; //XXX
    uint32_t dataPointer = 0; //XXX
    uint32_t dataSize = 0;
    uint32_t result = 0;
    bool ok = true;

    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &pluginNamePointer, sizeof(pluginNamePointer));
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &dataPointer, sizeof(dataPointer));
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EDX]), &dataSize, sizeof(dataSize));
    if(!ok) {
        s2e()->getWarningsStream(state)
            << "ERROR: symbolic arguments was passed to s2e_op invokePlugin opcode\n";
        result = 1;
        goto fail;
    }


    if (!state->readString(pluginNamePointer, pluginName)) {
        s2e()->getWarningsStream(state)
            << "ERROR: invokePlugin could not read name of plugin to invoke\n";
        result = 2;
        goto fail;
    }

    plugin = s2e()->getPlugin(pluginName);
    if (!plugin) {
        s2e()->getWarningsStream(state)
            << "ERROR: invokePlugin could not find plugin " << pluginName << "\n";
        result = 3;
        goto fail;
    }

    iface = dynamic_cast<BaseInstructionsPluginInvokerInterface*>(plugin);

    if (!iface) {
        s2e()->getWarningsStream(state)
            << "ERROR: " << pluginName << " is not an instance of BaseInstructionsPluginInvokerInterface\n";
        result = 4;
        goto fail;
    }

    iface->handleOpcodeInvocation(state, dataPointer, dataSize);

 fail:
    state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &result, sizeof(result));
}

/** Handle s2e_op instruction. Instructions:
    0f 3f XX XX XX XX XX XX XX XX
    XX: opcode
 */
void BaseInstructions::handleBuiltInOps(S2EExecutionState* state, uint64_t opcode)
{
    switch((opcode>>8) & 0xFF) {
        case 0: { /* s2e_check */
                uint32_t v = 1;
                state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &v, 4);
            }
            break;
        case 1: state->enableSymbolicExecution(); break;
        case 2: state->disableSymbolicExecution(); break;

        case 3: { /* s2e_make_symbolic */
            makeSymbolic(state, false);
            break;
        }

        case 4: { /* s2e_is_symbolic */
            isSymbolic(state);
            break;
        }

        case 5: { /* s2e_get_path_id */
            state->writeCpuRegister(offsetof(CPUX86State, regs[R_EAX]),
                klee::ConstantExpr::create(state->getID(), klee::Expr::Int32));
            break;
        }

        case 6: { /* s2e_kill_state */
            killState(state);
            break;
            }

        case 7: { /* s2e_print_expression */
            printExpression(state);
            break;
        }

        case 8: { //Print memory contents
            printMemory(state);
            break;
        }

        case 9: {
            state->enableForking();
            break;
        }

        case 0xa: {
            state->disableForking();
            break;
        }

        case 0xb: {
            invokePlugin(state);
            break;
        }

        case 0x10: { /* s2e_print_message */
            printMessage(state, opcode >> 16);
            break;
        }

        case 0x11: { /* s2e_make_concolic */
            makeSymbolic(state, true);
            break;
        }

        case 0x20: /* concretize */
            concretize(state, true);
            break;

        case 0x21: { /* replace an expression by one concrete example */
            concretize(state, false);
            break;
        }

        case 0x30: { /* Get number of active states */
            uint32_t count = s2e()->getExecutor()->getStatesCount();
            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &count, sizeof(uint32_t));
            break;
        }

        case 0x31: { /* Get number of active S2E instances */
            uint32_t count = s2e()->getCurrentProcessCount();
            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &count, sizeof(uint32_t));
            break;
        }
        case 0x32: { /* Sleep for a given number of seconds */
           sleep(state);
           break;
        }

        case 0x50: { /* disable/enable timer interrupt */
            uint64_t disabled = opcode >> 16;
            if(disabled)
                s2e()->getMessagesStream(state) << "Disabling timer interrupt\n";
            else
                s2e()->getMessagesStream(state) << "Enabling timer interrupt\n";
            state->writeCpuState(CPU_OFFSET(timer_interrupt_disabled),
                                 disabled, 8);
            break;
        }
        case 0x51: { /* disable/enable all apic interrupts */
            uint64_t disabled = opcode >> 16;
            if(disabled)
                s2e()->getMessagesStream(state) << "Disabling all apic interrupt\n";
            else
                s2e()->getMessagesStream(state) << "Enabling all apic interrupt\n";
            state->writeCpuState(CPU_OFFSET(all_apic_interrupts_disabled),
                                 disabled, 8);
            break;
        }

        case 0x52: { /* Gets the current S2E memory object size (in power of 2) */
                uint32_t size = S2E_RAM_OBJECT_BITS;
                state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &size, 4);
                break;
        }

        case 0x70: /* merge point */
            state->jumpToSymbolicCpp();
            s2e()->getExecutor()->queueStateForMerge(state);
            break;
			
		case 0x80: { /* s2e_get_int_overflow_example，用来计算出造成整数溢出的例子，需要知道该变量的名字 */
        	getIntOverflowExample(state);
            break;
        }

        default:
            s2e()->getWarningsStream(state)
                << "BaseInstructions: Invalid built-in opcode " << hexval(opcode) << '\n';
            break;
    }
}

void BaseInstructions::onCustomInstruction(S2EExecutionState* state, 
        uint64_t opcode)
{
    uint8_t opc = (opcode>>8) & 0xFF;
    if (opc <= 0x80) {//upadated by wzy,0x70
        handleBuiltInOps(state, opcode);
    }
}

}
}
