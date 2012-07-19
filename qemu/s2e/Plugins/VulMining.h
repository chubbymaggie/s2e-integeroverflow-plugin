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

#ifndef _VulMining_PLUGIN_H_

#define _VulMining_PLUGIN_H_

#include <s2e/Plugins/ModuleDescriptor.h>

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/OSMonitor.h>//这里包含了OSMonitor



#include <vector>

typedef uint32_t target_ulong;
//为了调用monitor.c中的函数，这里需要在c++的头函数中重新声明
extern "C" void test_1(void);
extern "C" void target_disas(FILE *out, target_ulong code, target_ulong size, int flags);


namespace s2e {
namespace plugins {

class VulMining:public Plugin //这里是需要修改的一个地方
{
    S2E_PLUGIN

public:


private:

    sigc::connection m_onTranslateInstruction;
    //这里暂且先设置为64位吧，如果有问题，后面再进行修改
    uint64_t m_ReceiveLastPC;
    std::string m_ReceiveFirst10Byte;
    uint64_t m_TerminatePC;
    std::string m_DisasTerminatePC;

	typedef std::pair<std::string, std::vector<unsigned char> > VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;


    //这里以receive函数为例子
    //这个类当中包含了代码地址和缓冲区当中的内容
    //这个地址是指receive函数的最后一条地址，内容是接受到的前面几个字符，比如说是10个；
    typedef std::pair<uint64_t, std::string> FunInputsPair;
    typedef std::vector<FunInputsPair> FunInputVector;
    FunInputVector m_TaintSrcFunInputVector;


    //下面是assert断言的例子
    typedef std::pair<std::string, uint64_t> AssertFunPair;
    typedef std::vector<AssertFunPair> AssertFunVector;
    AssertFunVector m_assertFunVector;

    //这里是terminate的类型
    typedef std::pair<uint64_t, std::string> TerminatePair;
    typedef std::vector<TerminatePair> TerminateVector;
    TerminateVector m_TerminateVector;

    sigc::connection m_sig_setWSAReceiveInputsSymbolicVar;

    sigc::connection m_sig_setReceiveInputsSymbolicVar;

public:
    VulMining(S2E* s2e): Plugin(s2e) {}//这里是需要修改的一个地方
    virtual ~VulMining();
    void initialize();

    void makeFunInputsSymbolic(ExecutionSignal *signal,
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t pc);

    void makeReceiveInputsSymbolic(ExecutionSignal *signal,
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t pc);

    void makeWSAReceiveInputsSymbolic(ExecutionSignal *signal,
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t pc);

    void onTranslateInstructionStart(ExecutionSignal *signal,
                                     S2EExecutionState *state,
                                     TranslationBlock *tb,
                                     uint64_t pc);

    void setReceiveInputsSymbolicVar(S2EExecutionState *state, uint64_t pc);
    void setWSAReceiveInputsSymbolicVar(S2EExecutionState *state, uint64_t pc);


    void setDisableForking(S2EExecutionState *state, uint64_t pc);
    void assertMemcpy(S2EExecutionState *state, uint64_t pc);
    void assertMalloc(S2EExecutionState *state, uint64_t pc);
    void assert_string_alloc(S2EExecutionState *state, uint64_t pc);

    void disasPC(uint64_t pc);

    void terminateForking(ExecutionSignal *signal,
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t pc);

    void assertVulnerablePoints(ExecutionSignal *signal,
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t pc);





};



} // namespace plugins
} // namespace s2e


#endif
