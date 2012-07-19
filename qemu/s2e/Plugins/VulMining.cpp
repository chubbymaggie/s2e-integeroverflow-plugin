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
 *    wzy <wuzhiyong0127@gmail.com>
 *
 * All contributors are listed in S2E-AUTHORS file.
 *
 */

/**
This plugin is used to implement vulnerability mining. It includes three parts:
1) the start point to make input symbolic, which also can be understood as taint source;
2) assert part, put some rules here to finding the bugs of interesting points, like vulnerable functions and loops;
3) termination points where disable forking or terminate;
 */

extern "C" {
#include "config.h"
#include "qemu-common.h"
}


#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Opcodes.h>
#include "VulMining.h"

#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <klee/Solver.h>
//#include <klee/Executor.h>

//但是，头文件恰是在这里包含
#include "../../monitor.h"
#include "../../disas.h"

#include <sstream>

using namespace std;

using namespace s2e;
using namespace s2e::plugins;

S2E_DEFINE_PLUGIN(VulMining, "Plugin for monitoring raw module events", "Interceptor");

std::string itoa(int value, int base);

VulMining::~VulMining()
{

}


//初始化
void VulMining::initialize()
{
    //1. 这里打算把VulMining几个相关的成员变量初始化一下
	//1.1 WSAReceive,下面这个参数值适用于某平台
	//FunInputsPair tmpFIPair1( 0x71b694f7, "4d616e616765");//这里打算用16进制的表示方法来对比一下:"Manage"
	//m_TaintSrcFunInputVector.push_back( tmpFIPair1);

	//1.1 receive
	FunInputsPair tmpFIPair1( 0x71ab6800, "31323334");//这里打算用16进制的表示方法来对比一下:"1234"
	m_TaintSrcFunInputVector.push_back( tmpFIPair1);

	//2. assert
	//AssertFunPair tmpAFPair1( "assertMemcpy", 0x004059A0);//0x004059A0��Ҫ��____cd
	AssertFunPair tmpAFPair2( "assertMalloc", 0x403c80);//malloc的第一条指令地址
	//AssertFunPair tmpAFPair2( "assert_string_alloc", 0x64001df0);
	//m_assertFunVector.push_back( tmpAFPair1);
	m_assertFunVector.push_back( tmpAFPair2);
	

	//3. terminate
	TerminatePair tmpTPair1( 0x4010BD, "0x004010d5:  push");//还需要进一步验证
	m_TerminateVector.push_back( tmpTPair1);



    //问题：既然这里对TranslateInstructionStart进行插桩了，那么，对于每一个翻译的开始的指令，怎么就不行呢？
    m_onTranslateInstruction = s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &VulMining::onTranslateInstructionStart));

}


void VulMining::makeFunInputsSymbolic(ExecutionSignal *signal,
        S2EExecutionState *state,
        TranslationBlock *tb,
        uint64_t pc)
{

	//这里是处理receive函数的handle
	makeReceiveInputsSymbolic( signal, state, tb, pc);

	//这里是处理WSAreceive函数的handle
	//makeWSAReceiveInputsSymbolic( signal, state, tb, pc);



	//这里是处理read函数的handle


}

//Receive 函数
void VulMining::makeReceiveInputsSymbolic(ExecutionSignal *signal,
        S2EExecutionState *state,
        TranslationBlock *tb,
        uint64_t pc)
{
	//首先，这里需要把receive函数中的几个输入给打印出来


	FunInputVector::iterator it;
	//下一步，如果对多个TaintSrc进行处理的话，通过循环可能是不够的，因为，信号量的命名是有问题的；
	for (it = m_TaintSrcFunInputVector.begin(); it != m_TaintSrcFunInputVector.end(); ++it)
	{
        const FunInputsPair &vp = *it;
        if ( pc == vp.first)
        {
    		char *buf;
    		long lSize;
    		long result;

    		//生成一个FILE结构
    		FILE *m_logFile;
    		m_logFile = fopen("/home/wzy/disas.txt", "w+");
    		target_disas( m_logFile, pc, 1, 0);
    		fclose(m_logFile);

    		m_logFile = fopen("/home/wzy/disas.txt", "r");
    		//获取文件大小
    		fseek (m_logFile , 0 , SEEK_END);
    		lSize = ftell (m_logFile);
    		rewind (m_logFile);
    //
    		buf = (char*) malloc (sizeof(char)*lSize);
    		memset( buf, 0, sizeof(char)*lSize);
    	    if (buf == NULL)
    	    	{fputs ("Memory error",stderr); exit (2);}
    //
    		result = fread (buf,1,lSize,m_logFile);
    		if (result != lSize)
    			{fputs ("Reading error",stderr); exit (3);}
    //
    		fclose(m_logFile);//为何fclose会出错呢？

    		//其次，这里开始发射信号，设置符号变量
    		m_sig_setReceiveInputsSymbolicVar = signal->connect(sigc::mem_fun(*this, &VulMining::setReceiveInputsSymbolicVar));

    		free(buf);
        }
	}



}


//WSAReceive函数
void VulMining::makeWSAReceiveInputsSymbolic(ExecutionSignal *signal,
        S2EExecutionState *state,
        TranslationBlock *tb,
        uint64_t pc)
{
	//首先，这里需要把receive函数中的几个输入给打印出来


	FunInputVector::iterator it;

	for (it = m_TaintSrcFunInputVector.begin(); it != m_TaintSrcFunInputVector.end(); ++it)
	{
        const FunInputsPair &vp = *it;
        if ( pc == vp.first)
        {
    		char *buf;
    		long lSize;
    		long result;

    		//生成一个FILE结构
    		FILE *m_logFile;
    		m_logFile = fopen("/home/wzy/disas.txt", "w+");
    		target_disas( m_logFile, pc, 1, 0);
    		fclose(m_logFile);

    		m_logFile = fopen("/home/wzy/disas.txt", "r");
    		//获取文件大小
    		fseek (m_logFile , 0 , SEEK_END);
    		lSize = ftell (m_logFile);
    		rewind (m_logFile);
    //
    		buf = (char*) malloc (sizeof(char)*lSize);
    		memset( buf, 0, sizeof(char)*lSize);
    	    if (buf == NULL)
    	    	{fputs ("Memory error",stderr); exit (2);}
    //
    		result = fread (buf,1,lSize,m_logFile);
    		if (result != lSize)
    			{fputs ("Reading error",stderr); exit (3);}
    //
    		fclose(m_logFile);//为何fclose会出错呢？

    		//其次，这里开始发射信号，设置符号变量
    		m_sig_setReceiveInputsSymbolicVar = signal->connect(sigc::mem_fun(*this, &VulMining::setWSAReceiveInputsSymbolicVar));

    		free(buf);
        }
	}



}



//我觉得就通过对这个函数实现稍微的修改，就可以实现我想达到的那个目标
void VulMining::terminateForking(ExecutionSignal *signal,
                                                   S2EExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc)
{
	//查看是否是关心的pc，如果是，则disable，这里可以有多个terminate的地方；
	//该参数暂时没有用到
	//uint64_t terminatePC;

	TerminateVector::iterator it;

	for (it = m_TerminateVector.begin(); it != m_TerminateVector.end(); ++it)
	{
        const TerminatePair &vp = *it;
        if ( pc == vp.first)
        {
    		char *buf;
    		long lSize;
    		long result;

    		//生成一个FILE结构
    		FILE *m_logFile;
    		m_logFile = fopen("/home/wzy/disas.txt", "w+");
    		target_disas( m_logFile, pc, 1, 0);
    		fclose(m_logFile);


    		m_logFile = fopen("/home/wzy/disas.txt", "r");
    		//获取文件大小
    		fseek (m_logFile , 0 , SEEK_END);
    		lSize = ftell (m_logFile);
    		rewind (m_logFile);


    		buf = (char*) malloc (sizeof(char)*lSize);
    		memset( buf, 0, sizeof(char)*lSize);
    	    if (buf == NULL)
    	    	{fputs ("Memory error",stderr); exit (2);}

    		result = fread (buf,1,lSize,m_logFile);
    		if (result != lSize)
    			{fputs ("Reading error",stderr); exit (3);}


    		fclose(m_logFile);//为何fclose会出错呢？

    		s2e()->getMessagesStream() <<"buf: "<<buf<<'\n';
    		s2e()->getMessagesStream() <<"vp.second.c_str(): "<<vp.second.c_str()<<'\n';

    		//第2层过滤
    		//读取第一行
    		if( strstr( buf, vp.second.c_str()))
    		{
    			//disableForking
    			signal->connect(sigc::mem_fun(*this, &VulMining::setDisableForking));
    		}
    		free(buf);
        }
	}




}


//我觉得就通过对这个函数实现稍微的修改，就可以实现我想达到的那个目标
void VulMining::onTranslateInstructionStart(ExecutionSignal *signal,
                                                   S2EExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc)
{
	//该参数暂时也没有用到
	//target_ulong code;

	//1. to debug, by wzy
	s2e()->getDebugStream()<<"translation, pc: "<<hexval(pc);
	//disasPC(pc);

	//2. set symbolic
	makeFunInputsSymbolic( signal, state, tb, pc);

	//3. assert
	assertVulnerablePoints( signal, state, tb, pc);


	//4. terminate
	terminateForking( signal, state, tb, pc);//////////////////////////////////////////////////


}

void VulMining::disasPC(uint64_t pc)
{
	char *buf;
	long lSize;
	long result;
	//生成一个FILE结构
	FILE *m_logFile;
	m_logFile = fopen("/home/wzy/disas.txt", "w+");
	target_disas( m_logFile, pc, 1, 0);
	fclose(m_logFile);


	m_logFile = fopen("/home/wzy/disas.txt", "r");
	//获取文件大小
	fseek (m_logFile , 0 , SEEK_END);
	lSize = ftell (m_logFile);
	rewind (m_logFile);


	buf = (char*) malloc (sizeof(char)*lSize);
	memset( buf, 0, sizeof(char)*lSize);
    if (buf == NULL)
    	{fputs ("Memory error",stderr); exit (2);}

	result = fread (buf,1,lSize,m_logFile);
	if (result != lSize)
		{fputs ("Reading error",stderr); exit (3);}


	fclose(m_logFile);//为何fclose会出错呢？

	s2e()->getDebugStream() <<"buf: "<<buf<<'\n';

	free(buf);

}


void VulMining::assertVulnerablePoints(ExecutionSignal *signal,
                                                   S2EExecutionState *state,
                                                   TranslationBlock *tb,
                                                   uint64_t pc)
{
	//1 循环获取各个assert函数的地址

	AssertFunVector::iterator it;

	for (it = m_assertFunVector.begin(); it != m_assertFunVector.end(); ++it)
	{
		//2 应用相应的函数，对其进行处理
        const AssertFunPair &vp = *it;
        if ( pc == vp.second)
        {
        	if (strstr("VulMining::assertMemcpy", vp.first.c_str()))
        	{
        		signal->connect(sigc::mem_fun(*this, &VulMining::assertMemcpy));
        	}
        	else if( strstr("VulMining::assertMalloc", vp.first.c_str()))
        	{
        		signal->connect(sigc::mem_fun(*this, &VulMining::assertMalloc));
        	}
        	else if( strstr("VulMining::assert_string_alloc", vp.first.c_str()))
        	{
        	    signal->connect(sigc::mem_fun(*this, &VulMining::assert_string_alloc));
        	}
        	else //assert_string_alloc
        	{
        		;
        	}
        }
	}




}


//这里给出了这样一个前提：即receive函数可能在多个地方被硬编码进去了，那么，这里就通过双层过滤的方法
//来确定是否setReceiveInputsSymbolicVar?

//recv的几个参数：
//int recv(
//  __in   SOCKET s,
//  __out  char *buf,
//  __in   int len,
//  __in   int flags
//);

void VulMining::setReceiveInputsSymbolicVar(S2EExecutionState *state, uint64_t pc)
{


	s2e()->getDebugStream()<<"running time, state->getPc(): "<<hexval(state->getPc())<<'\n';
	s2e()->getDebugStream()<<"running time, pc: "<<hexval(pc)<<'\n';

	s2e_dump_state();

	uint64_t address = 0, sp = 0;
	//uint64_t buf_addr = 0, size = 0;
	uint64_t param1_s = 0, param2_buf_addr = 0, param3_recv_len = 0;

    std::string buf;

	sp = state->getSp();
	address =sp + 0xc;

	//recv的第一个参数，该值是socket
	state->readMemoryConcrete(sp + 0x4, &param1_s, sizeof(uint32_t));
    //recv的第二个参数，该值存放buf的初始地址
	state->readMemoryConcrete(sp + 0x8, &param2_buf_addr, sizeof(uint32_t));
	//recv的第三个参数，该值存放的len
    state->readMemoryConcrete(sp + 0xc, &param3_recv_len, sizeof(uint32_t));

	s2e()->getMessagesStream() << "receive is called " << hexval(pc) <<'\n';

	char RecvData[65535] = {0};
	std::string RecvDataCast;//存放了转换成16进制字符串的数据

    if (0 == param3_recv_len) {
    	s2e()->getDebugStream() <<"Error: "<<'\n';
    	return;
    }

    int pos = 0;
    char tmp = 0;

	for( uint64_t j = 0; j < param3_recv_len; j++)
	{
		state->readMemoryConcrete( param2_buf_addr + j, &tmp, 1);
		RecvData[pos] = tmp;
		RecvDataCast.append(itoa(tmp,16));
		pos = pos + 1;
	}

	FunInputVector::iterator it;

	for (it = m_TaintSrcFunInputVector.begin(); it != m_TaintSrcFunInputVector.end(); ++it)
	{
		const FunInputsPair &vp = *it;

		//debug
	    s2e()->getMessagesStream() <<"RecvDataCast.c_str(): "<<RecvDataCast.c_str()<<'\n';
	    s2e()->getMessagesStream() <<"vp.second.c_str(): "<<vp.second.c_str()<<'\n';


        if ( ( pc == vp.first) && strstr( RecvDataCast.c_str(), vp.second.c_str()))
        {

        	s2e()->getMessagesStream() << "setSymbolicVar pc " << hexval(pc) <<'\n'
        							   << "---------sp     : " << hexval(sp) <<'\n'
        							   << "---------param1_s : " << hexval(param1_s) <<'\n'
        							   << "---------param2_buf_addr : " << hexval(param2_buf_addr) <<'\n'
        							   << "---------param3_recv_len : " << hexval(param3_recv_len) <<'\n';

        	//把Recv接收到的内容输出来
        	s2e()->getMessagesStream() << '\n' <<"RecvDataCast: "<<RecvDataCast.c_str();

        	state->setPc(pc);
        	state->jumpToSymbolicCpp();

        	//这里需要创建一系列的符号化的输入变量
        	uint64_t symVarNum = param3_recv_len;
        	char name[20];
        	//
        	for( uint64_t i = 0; i < symVarNum; i++)
        	{
        		//这里声明一个局部变量
        		memset( name, 0, 20);
        		//sprintf( name, "buf[%d]", i);
				sprintf( name, "buf[%lu]", i);
				//createSymbolicValue函数的参数和旧版本的参数顺序颠倒
        		klee::ref<klee::Expr> symb = state->createSymbolicValue( name, 8) ;//receive_size * 8
        		state->writeMemory(param2_buf_addr + i, symb);
        		s2e()->getMessagesStream() <<"symb: "<<symb<<'\n';
        	}

        	state->enableForking();

        	//m_sig_setReceiveInputsSymbolicVar.disconnect();
        }
        else
        {
        	;
        }

        //

	}


}


//这里给出了这样一个前提：即receive函数可能在多个地方被硬编码进去了，那么，这里就通过双层过滤的方法
//来确定是否setReceiveInputsSymbolicVar?
void VulMining::setWSAReceiveInputsSymbolicVar(S2EExecutionState *state, uint64_t pc)
{



	s2e()->getDebugStream()<<"running time, state->getPc(): "<<hexval(state->getPc())<<'\n';
	s2e()->getDebugStream()<<"running time, pc: "<<hexval(pc)<<'\n';

	s2e_dump_state();

	uint64_t value = 0, address = 0, size = 0, sp = 0;
	uint64_t param1 = 0, param2 = 0, receive_size = 0, dwBufferCount = 0, lpNumberofBytesRecvd = 0, NumberofBytesRecvd = 0;



	sp = state->getSp();
	address =sp + 0xc;

	state->readMemoryConcrete(sp + 0x4, &param1, sizeof(uint32_t));//param1的大小是4，这个值用来干什么的呢？
    state->readMemoryConcrete(sp + 0x8, &param2, sizeof(uint32_t));//param2存放的是__WSABUF中的数值
    state->readMemoryConcrete(sp + 0x0c, &dwBufferCount, sizeof(uint32_t));//dwBufferCount存放的是WSABUF的个数
    state->readMemoryConcrete(sp + 0x10, &lpNumberofBytesRecvd, sizeof(uint32_t));//dwBufferCount存放的是WSABUF的个数
    state->readMemoryConcrete(sp + 0x10, &NumberofBytesRecvd, sizeof(uint32_t));


    typedef struct __WSABUF{
    	uint32_t len;
    	uint32_t buf;
    } WSABUF, *LPWSABUF;

    WSABUF* wsabufs;

    wsabufs = (LPWSABUF)malloc(dwBufferCount * sizeof(WSABUF));

    for( uint64_t i = 0; i < dwBufferCount; i++)
    {
    	state->readMemoryConcrete(param2 + i * sizeof(WSABUF), &wsabufs[i], sizeof(WSABUF));//输出来的是其内容
    }

    //对每一个wsabufs[i]中buf中对值进行符号化


    receive_size = NumberofBytesRecvd;
    value = (uint64_t)wsabufs[0].buf;

    //s2e()->getMessagesStream() << "size of WSARecv is:" << sizeof(WSABUF) <<'\n';
	s2e()->getMessagesStream() << "WSARecv is called:" <<'\n';
	s2e()->getMessagesStream() << "dwBufferCount:" << dwBufferCount<<'\n';
	s2e()->getMessagesStream() << "wsabufs[0].len:" <<wsabufs[0].len<<'\n';




    char WSARecvData[65535] = {0};
    std::string WSARecvDataCast;

    //从m_receiveFunInputVector变量当中，把地址和buf当中的内容一个个取出来，并做比对，看其结果，再做进一步地分析。
    //这里应该做这样的一个事情，就是当WSARecv接收到一个数据包之后，就以16进制的形式把数据包中的内容打印出来，即可。
    int pos = 0;
    char tmp = 0;
    for( int i = 0; i < dwBufferCount; i++)
	{
		//value = (uint64_t)wsabufs[i].buf;
		//这里声明一个局部变量
		for( int j = 0; j < wsabufs[i].len; j++)
		{
			state->readMemoryConcrete( wsabufs[i].buf + j, &tmp, 1);
			WSARecvData[pos] = tmp;
			WSARecvDataCast.append(itoa(tmp,16));
			pos = pos + 1;
		}
	}


    //1
//    s2e()->getMessagesStream() << "1____WSARecvData: 0x";
//    for( int i = 0; i < pos; i++)
//    {
//    	s2e()->getMessagesStream() << hexval(WSARecvData[i] & 0xff, 1) << " ";
//    }

    //2
    s2e()->getMessagesStream() <<"2____WSARecvData: ";
    for( int i = 0; i < pos; i++)
    {
    	s2e()->getMessagesStream() << hexval((int8_t)(WSARecvData[i]))<<'\n';
    }
    s2e()->getMessagesStream() <<"WSARecvDataCast: "<<WSARecvDataCast.c_str()<<'\n';

    //return;//暂时先退出


	FunInputVector::iterator it;

	for (it = m_TaintSrcFunInputVector.begin(); it != m_TaintSrcFunInputVector.end(); ++it)
	{
		const FunInputsPair &vp = *it;

		//debug

	    s2e()->getMessagesStream() <<"vp.second.c_str(): "<<vp.second.c_str()<<'\n';


        if ( ( pc == vp.first) && strstr( WSARecvDataCast.c_str(), vp.second.c_str()))//进行过滤
        {

        	s2e()->getMessagesStream() << "setSymbolicVar pc " << hexval(pc) <<'\n'
        							   << "---------sp     : " << hexval(sp) <<'\n'
        							   << "---------param1 : " << hexval(param1) <<'\n'
        							   << "---------param2 : " << hexval(param2) << '\n'

        							   << "---------WSAreceive_size : " << hexval(receive_size) << '\n'

        							   << "---------WSAreceive_size value   : " << hexval(value) << '\n'
        							   << "---------symbolic size  : " << hexval(size) << '\n';

        	state->setPc(pc);
        	state->jumpToSymbolicCpp();

        	//这里需要创建一系列的符号化的输入变量
        	//symVarNum暂时没有用到
			//int symVarNum = receive_size;
        	char name[20];
        	//
        	for( int i = 0; i < dwBufferCount; i++)
        	//for( int i = 0; i < symVarNum; i++)
        	{
        		//value = (uint64_t)wsabufs[i].buf;
        		//这里声明一个局部变量
        		for( int j = 0; j < wsabufs[i].len; j++)

        			{
        				memset( name, 0, 20);
						sprintf( name, "buf[%d]", i*j);
						//参数的顺序改变
						klee::ref<klee::Expr> symb = state->createSymbolicValue( name, 8) ;//receive_size * 8
						state->writeMemory(wsabufs[i].buf + j, symb);//这里需要进一步的确认
						s2e()->getMessagesStream() <<"symb: "<<symb<<'\n';
        			}
        	}

        	//dwBufferCount





        	state->disableForking();

        	m_sig_setWSAReceiveInputsSymbolicVar.disconnect();
        }
        else
        {
        	;
        }
	}


}


void VulMining::setDisableForking(S2EExecutionState *state, uint64_t pc)
{
	state->disableForking();
	s2e()->getDebugStream()<<"disableForking: "<<hexval(pc)<<'\n';
}

void VulMining::assertMemcpy(S2EExecutionState *state, uint64_t pc)
{
	uint64_t value = 0, address = 0, sp = 0;
	uint64_t param1 = 0, param2 = 0, param3 = 0;

	//生成一个FILE结构
	FILE *m_logFile;
	m_logFile = fopen("/home/wzy/disas.txt", "w+");
	target_disas( m_logFile, pc, 6, 0);
	fclose(m_logFile);

	sp = state->getSp();
	address =sp + 0xc;

	state->readMemoryConcrete(sp + 0x4, &param1, sizeof(uint32_t));
    state->readMemoryConcrete(sp + 0x8, &param2, sizeof(uint32_t));
    state->readMemoryConcrete(sp + 0xc, &param3, sizeof(uint32_t));
    state->readMemoryConcrete(address, &value, sizeof(uint32_t));

	s2e()->getMessagesStream() << "assertMemcpy pc " << hexval(pc) <<'\n'
							   << "---------sp     : " << hexval(sp) <<'\n'
							   << "---------param1 : " << hexval(param1) <<'\n'
							   << "---------param2 : " << hexval(param2) <<'\n'
							   << "---------param3 : " << hexval(param3) <<'\n'
							   << "---------param3 address : " << hexval(address) <<'\n'
							   << "---------param3 value   : " << hexval(value) <<'\n';

    klee::ref<klee::Expr> symValue = state->readMemory(address, klee::Expr::Int32);//既然是符号化的值，这里如何把符号化的表达式输出来呢？
	s2e()->getMessagesStream() << "---------param3 symbolic value : " << symValue <<'\n';

	klee::ref<klee::Expr> cond = klee::SgtExpr::create(symValue, klee::ConstantExpr::create(0x20, symValue.get()->getWidth()));
	s2e()->getMessagesStream() << "---------assert cond : " << cond <<'\n';

	bool isTrue;
	if (!(s2e()->getExecutor()->getSolver()->mayBeTrue(klee::Query(state->constraints, cond), isTrue))) {
		s2e()->getMessagesStream() << "failed to assert the condition" <<'\n';
		return;
    }
	if (isTrue) {
		ConcreteInputs inputs;
		ConcreteInputs::iterator it;

		s2e()->getExecutor()->getSymbolicSolution(*state, inputs);
		s2e()->getMessagesStream() << "---------memcpy crash detected!" <<'\n'
								   << "---------input value : " <<'\n';
	    for (it = inputs.begin(); it != inputs.end(); ++it) {
	        const VarValuePair &vp = *it;
   		    s2e()->getMessagesStream() << "---------" << vp.first << " : ";

	        for (unsigned i=0; i<vp.second.size(); ++i) {
				 s2e()->getMessagesStream() << hexval((unsigned char) vp.second[i]) << " ";
        	}

   		    s2e()->getMessagesStream() <<'\n';


		}
	}
}
void VulMining::assertMalloc(S2EExecutionState *state, uint64_t pc)
{
	uint64_t sp, param1, param1Addr,retaddr;
	bool result;

	sp = state->getSp();
	param1Addr = sp + 0x4;
	state->readMemoryConcrete(sp, &retaddr, sizeof(uint32_t));
	//s2e()->getWarningsStream() << " the address of call malloc is:   " << hexval(retaddr)<<std::endl;
	//s2e()->getWarningsStream() << "assertMalloc is called, the running pc: " << hexval(pc)<<std::endl;


	result = state->readMemoryConcrete(param1Addr, &param1, sizeof(uint32_t));

	//s2e()->getWarningsStream() << " the param of malloc is:   " <<hexval(param1)<<std::endl;

	//如果成功，表示这里是具体值，还不是符号化的值，则不为外部控制，则直接返回
	if( result )
	{
		return;
	}

	s2e()->getMessagesStream() << "assertMalloc is called " <<'\n';

	s2e()->getMessagesStream() << "assertMalloc pc " << hexval(pc) <<'\n'
							   << "---------sp     : " << hexval(sp) <<'\n'
							   << "---------param1 : " << hexval(param1) <<'\n'
							   << "---------param1 address : " << hexval(param1Addr) <<'\n';

    klee::ref<klee::Expr> symValue = state->readMemory(param1Addr, klee::Expr::Int32);
	s2e()->getMessagesStream() << "---------param1 symbolic value : " << symValue <<'\n';

	klee::ref<klee::Expr> symValue_1 = klee::ZExtExpr::create(symValue, klee::Expr::Int64);
	klee::ref<klee::Expr> symValue_2 = klee::SExtExpr::create(symValue, klee::Expr::Int64);

	// klee::ref<klee::Expr> cond = klee::EqExpr::create(symValue, klee::ConstantExpr::create(0x8, symValue.get()->getWidth()));
	klee::ref<klee::Expr> cond_1 = klee::UgtExpr::create(symValue_1, klee::ConstantExpr::create(0xffffffff, klee::Expr::Int64));
	klee::ref<klee::Expr> cond_2 = klee::SgtExpr::create(symValue_2, klee::ConstantExpr::create(0x7fffffff, klee::Expr::Int64));
	//klee::ref<klee::Expr> cond = klee::EqExpr::create(klee::OrExpr::create(cond_1, cond_2), klee::ConstantExpr::create(0x1, klee::Expr::Bool));
	s2e()->getMessagesStream() << "---------assert cond : " << cond_1 <<'\n';

	bool isTrue;
	if (!(s2e()->getExecutor()->getSolver()->mayBeTrue(klee::Query(state->constraints, cond_1), isTrue))) {
		s2e()->getMessagesStream() << "Failed to assert the condition" <<'\n';
		return;
    }
	if (isTrue) {
		ConcreteInputs inputs;
		ConcreteInputs::iterator it;

		s2e()->getExecutor()->addConstraint(*state, cond_1);

		s2e()->getExecutor()->getSymbolicSolution(*state, inputs);
		s2e()->getMessagesStream() << "---------malloc crash detected!" <<'\n'
								   << "---------input value : " <<'\n';
	    for (it = inputs.begin(); it != inputs.end(); ++it) {
	        const VarValuePair &vp = *it;
   		    s2e()->getMessagesStream() << "---------" << vp.first << " : ";

	        for (unsigned i=0; i<vp.second.size(); ++i) {
				 s2e()->getMessagesStream() << hexval((unsigned char) vp.second[i]) << " ";
        	}
   		    s2e()->getMessagesStream() <<'\n';
		}
	}
}



void VulMining::assert_string_alloc(S2EExecutionState *state, uint64_t pc)
{
	uint64_t sp, param1, param1Addr;
	bool result;

	sp = state->getSp();
	param1Addr = sp + 0x4;

	//s2e()->getWarningsStream() << "assert_string_alloc is called, the running pc: " << hexval(pc)<<std::endl;

	result = state->readMemoryConcrete(param1Addr, &param1, sizeof(uint32_t));
	//如果成功，表示这里是具体值，还不是符号化的值，则不为外部控制，则直接返回
	if( result )
	{
		return;
	}

	s2e()->getWarningsStream() << "assert_string_alloc is called " <<'\n';

	s2e()->getWarningsStream() << "assert_string_alloc pc " << hexval(pc) <<'\n'
							   << "---------sp     : " << hexval(sp) <<'\n'
							   << "---------param1 : " << hexval(param1) <<'\n'
							   << "---------param1 address : " << hexval(param1Addr) <<'\n';

    klee::ref<klee::Expr> symValue = state->readMemory(param1Addr, klee::Expr::Int32);
	s2e()->getWarningsStream() << "---------param1 symbolic value : " << symValue <<'\n';

	klee::ref<klee::Expr> symValue_1 = klee::ZExtExpr::create(symValue, klee::Expr::Int64);
	klee::ref<klee::Expr> symValue_2 = klee::SExtExpr::create(symValue, klee::Expr::Int64);

	// klee::ref<klee::Expr> cond = klee::EqExpr::create(symValue, klee::ConstantExpr::create(0x8, symValue.get()->getWidth()));
	klee::ref<klee::Expr> cond_1 = klee::UgtExpr::create(symValue_1, klee::ConstantExpr::create(0xffffffff, klee::Expr::Int64));
	klee::ref<klee::Expr> cond_2 = klee::SgtExpr::create(symValue_2, klee::ConstantExpr::create(0x7fffffff, klee::Expr::Int64));
	klee::ref<klee::Expr> cond = klee::EqExpr::create(klee::OrExpr::create(cond_1, cond_2),
													  klee::ConstantExpr::create(0x1, klee::Expr::Bool));
	s2e()->getMessagesStream() << "---------assert cond : " << cond <<'\n';

	bool isTrue;
	if (!(s2e()->getExecutor()->getSolver()->mayBeTrue(klee::Query(state->constraints, cond), isTrue))) {
		s2e()->getWarningsStream() << "Failed to assert the condition" <<'\n';
		return;
    }
	if (isTrue) {
		bool res_1;
		ConcreteInputs inputs;
		ConcreteInputs::iterator it;

		s2e()->getExecutor()->addConstraint(*state, cond);

		res_1 = s2e()->getExecutor()->getSymbolicSolution(*state, inputs);
		if (res_1 == true) {
			s2e()->getMessagesStream() << "getSymbolicSolution Success!" <<'\n';
		} else {
			s2e()->getMessagesStream() << "getSymbolicSolution Failed!!!" <<'\n';
		}

		s2e()->getWarningsStream() << "---------assert_string_alloc crash detected!" <<'\n'
								   << "---------input value : " <<'\n';
	    for (it = inputs.begin(); it != inputs.end(); ++it) {
	        const VarValuePair &vp = *it;
   		    s2e()->getWarningsStream() << "---------" << vp.first << " : ";

	        for (unsigned i=0; i<vp.second.size(); ++i) {
				 s2e()->getWarningsStream() << itoa(vp.second[i], 16).c_str()<< " ";
        	}
   		    s2e()->getWarningsStream() <<'\n';
		}
	}
}


std::string itoa(int value, int base) {



	enum { kMaxDigits = 35 };

	std::string buf;

	buf.reserve( kMaxDigits ); // Pre-allocate enough space.



	// check that the base if valid

	if (base < 2 || base > 16) return buf;





	int quotient = value;



	// Translating number to string with base:

	do {

		buf += "0123456789abcdef"[ std::abs( quotient % base ) ];

		quotient /= base;

	} while ( quotient );



	// Append the negative sign for base 10

	if ( value < 0 && base == 10) buf += '-';



	std::reverse( buf.begin(), buf.end() );

	return buf;

}

//readCpuRegister(offsetof(CPUState, regs[R_EBX]), klee::Expr::Int32) <<'\n';
