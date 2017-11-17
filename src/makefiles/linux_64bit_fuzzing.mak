# SoftEther VPN Source Code
# 
# Copyright (c) 2012-2017 SoftEther VPN Project at University of Tsukuba, Japan.
# Copyright (c) 2012-2017 Daiyuu Nobori.
# All Rights Reserved.
# 
# http://www.softether.org/
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License version 2
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# 
# Platform: os=Linux, bits=64bit

# Variables

#CC=gcc

CC=clang
CXX=clang++
FUZZFLAGS=-DFUZZING -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,pc-table,edge -fsanitize=address -g
LIBFUZZER_A=libFuzzer.a

ifeq ($(SAN),MEM)
	FUZZFLAGS=-DFUZZING -DFUZZING_MSAN -fsanitize=memory -g
else ifeq ($(SAN),NO)
	FUZZFLAGS=-DFUZZING -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,pc-table,edge -g
else
	FUZZFLAGS=-DFUZZING -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,pc-table,edge -fsanitize=address -fsanitize=undefined -g
endif


OPTIONS_COMPILE_DEBUG=$(FUZZFLAGS) -D_DEBUG -DDEBUG -DUNIX -DUNIX_LINUX -DCPU_64 -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./src/ -I./src/Cedar/ -I./src/Mayaqua/ -g -fsigned-char -m64

OPTIONS_LINK_DEBUG=-g -fsigned-char -m64 -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz

OPTIONS_COMPILE_RELEASE=$(FUZZFLAGS) -DNDEBUG -DVPN_SPEED -DUNIX -DUNIX_LINUX -DCPU_64 -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./src/ -I./src/Cedar/ -I./src/Mayaqua/ -O2 -fsigned-char -m64

OPTIONS_LINK_RELEASE=-O2 -fsigned-char -m64 -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz $(FUZZFLAGS)

ifeq ($(DEBUG),YES)
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_DEBUG)
	OPTIONS_LINK=$(OPTIONS_LINK_DEBUG)
else
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_RELEASE)
	OPTIONS_LINK=$(OPTIONS_LINK_RELEASE)
endif

# Files
HEADERS_MAYAQUA=src/Mayaqua/Cfg.h src/Mayaqua/cryptoki.h src/Mayaqua/Encrypt.h src/Mayaqua/FileIO.h src/Mayaqua/intelaes/iaesni.h src/Mayaqua/Internat.h src/Mayaqua/Kernel.h src/Mayaqua/Mayaqua.h src/Mayaqua/MayaType.h src/Mayaqua/Memory.h src/Mayaqua/Microsoft.h src/Mayaqua/Network.h src/Mayaqua/Object.h src/Mayaqua/OS.h src/Mayaqua/Pack.h src/Mayaqua/pkcs11.h src/Mayaqua/pkcs11f.h src/Mayaqua/pkcs11t.h src/Mayaqua/Secure.h src/Mayaqua/Str.h src/Mayaqua/Table.h src/Mayaqua/TcpIp.h src/Mayaqua/Tick64.h src/Mayaqua/Tracking.h src/Mayaqua/TunTap.h src/Mayaqua/Unix.h src/Mayaqua/Win32.h src/Mayaqua/zlib/zconf.h src/Mayaqua/zlib/zlib.h
HEADERS_CEDAR=src/Cedar/Account.h src/Cedar/Admin.h src/Cedar/AzureClient.h src/Cedar/AzureServer.h src/Cedar/Bridge.h src/Cedar/BridgeUnix.h src/Cedar/BridgeWin32.h src/Cedar/Cedar.h src/Cedar/CedarPch.h src/Cedar/CedarType.h src/Cedar/Client.h src/Cedar/CM.h src/Cedar/CMInner.h src/Cedar/Command.h src/Cedar/Connection.h src/Cedar/Console.h src/Cedar/Database.h src/Cedar/DDNS.h src/Cedar/EM.h src/Cedar/EMInner.h src/Cedar/EtherLog.h src/Cedar/Hub.h src/Cedar/Interop_OpenVPN.h src/Cedar/Interop_SSTP.h src/Cedar/IPsec.h src/Cedar/IPsec_EtherIP.h src/Cedar/IPsec_IKE.h src/Cedar/IPsec_IkePacket.h src/Cedar/IPsec_IPC.h src/Cedar/IPsec_L2TP.h src/Cedar/IPsec_PPP.h src/Cedar/IPsec_Win7.h src/Cedar/IPsec_Win7Inner.h src/Cedar/Layer3.h src/Cedar/Link.h src/Cedar/Listener.h src/Cedar/Logging.h src/Cedar/Nat.h src/Cedar/NativeStack.h src/Cedar/netcfgn.h src/Cedar/netcfgx.h src/Cedar/NM.h src/Cedar/NMInner.h src/Cedar/NullLan.h src/Cedar/Protocol.h src/Cedar/Radius.h src/Cedar/Remote.h src/Cedar/Sam.h src/Cedar/SecureInfo.h src/Cedar/SecureNAT.h src/Cedar/SeLowUser.h src/Cedar/Server.h src/Cedar/Session.h src/Cedar/SM.h src/Cedar/SMInner.h src/Cedar/SW.h src/Cedar/SWInner.h src/Cedar/UdpAccel.h src/Cedar/UT.h src/Cedar/VG.h src/Cedar/Virtual.h src/Cedar/VLan.h src/Cedar/VLanUnix.h src/Cedar/VLanWin32.h src/Cedar/WaterMark.h src/Cedar/WebUI.h src/Cedar/Win32Com.h src/Cedar/winpcap/bittypes.h src/Cedar/winpcap/bucket_lookup.h src/Cedar/winpcap/count_packets.h src/Cedar/winpcap/Devioctl.h src/Cedar/winpcap/Gnuc.h src/Cedar/winpcap/ip6_misc.h src/Cedar/winpcap/memory_t.h src/Cedar/winpcap/normal_lookup.h src/Cedar/winpcap/Ntddndis.h src/Cedar/winpcap/Ntddpack.h src/Cedar/winpcap/Packet32.h src/Cedar/winpcap/pcap.h src/Cedar/winpcap/pcap-bpf.h src/Cedar/winpcap/pcap-int.h src/Cedar/winpcap/pcap-stdinc.h src/Cedar/winpcap/pthread.h src/Cedar/winpcap/remote-ext.h src/Cedar/winpcap/sched.h src/Cedar/winpcap/semaphore.h src/Cedar/winpcap/tcp_session.h src/Cedar/winpcap/time_calls.h src/Cedar/winpcap/tme.h src/Cedar/winpcap/Win32-Extensions.h src/Cedar/WinUi.h src/Cedar/Wpc.h
OBJECTS_MAYAQUA=tmp/objs/Mayaqua/Cfg.o tmp/objs/Mayaqua/Encrypt.o tmp/objs/Mayaqua/FileIO.o tmp/objs/Mayaqua/Internat.o tmp/objs/Mayaqua/Kernel.o tmp/objs/Mayaqua/Mayaqua.o tmp/objs/Mayaqua/Memory.o tmp/objs/Mayaqua/Microsoft.o tmp/objs/Mayaqua/Network.o tmp/objs/Mayaqua/Object.o tmp/objs/Mayaqua/OS.o tmp/objs/Mayaqua/Pack.o tmp/objs/Mayaqua/Secure.o tmp/objs/Mayaqua/Str.o tmp/objs/Mayaqua/Table.o tmp/objs/Mayaqua/TcpIp.o tmp/objs/Mayaqua/Tick64.o tmp/objs/Mayaqua/Tracking.o tmp/objs/Mayaqua/Unix.o tmp/objs/Mayaqua/Win32.o
OBJECTS_CEDAR=tmp/objs/Cedar/Account.o tmp/objs/Cedar/Admin.o tmp/objs/Cedar/AzureClient.o tmp/objs/Cedar/AzureServer.o tmp/objs/Cedar/Bridge.o tmp/objs/Cedar/BridgeUnix.o tmp/objs/Cedar/BridgeWin32.o tmp/objs/Cedar/Cedar.o tmp/objs/Cedar/CedarPch.o tmp/objs/Cedar/Client.o tmp/objs/Cedar/CM.o tmp/objs/Cedar/Command.o tmp/objs/Cedar/Connection.o tmp/objs/Cedar/Console.o tmp/objs/Cedar/Database.o tmp/objs/Cedar/DDNS.o tmp/objs/Cedar/EM.o tmp/objs/Cedar/EtherLog.o tmp/objs/Cedar/Hub.o tmp/objs/Cedar/Interop_OpenVPN.o tmp/objs/Cedar/Interop_SSTP.o tmp/objs/Cedar/IPsec.o tmp/objs/Cedar/IPsec_EtherIP.o tmp/objs/Cedar/IPsec_IKE.o tmp/objs/Cedar/IPsec_IkePacket.o tmp/objs/Cedar/IPsec_IPC.o tmp/objs/Cedar/IPsec_L2TP.o tmp/objs/Cedar/IPsec_PPP.o tmp/objs/Cedar/IPsec_Win7.o tmp/objs/Cedar/Layer3.o tmp/objs/Cedar/Link.o tmp/objs/Cedar/Listener.o tmp/objs/Cedar/Logging.o tmp/objs/Cedar/Nat.o tmp/objs/Cedar/NativeStack.o tmp/objs/Cedar/NM.o tmp/objs/Cedar/NullLan.o tmp/objs/Cedar/Protocol.o tmp/objs/Cedar/Radius.o tmp/objs/Cedar/Remote.o tmp/objs/Cedar/Sam.o tmp/objs/Cedar/SecureInfo.o tmp/objs/Cedar/SecureNAT.o tmp/objs/Cedar/SeLowUser.o tmp/objs/Cedar/Server.o tmp/objs/Cedar/Session.o tmp/objs/Cedar/SM.o tmp/objs/Cedar/SW.o tmp/objs/Cedar/UdpAccel.o tmp/objs/Cedar/UT.o tmp/objs/Cedar/VG.o tmp/objs/Cedar/Virtual.o tmp/objs/Cedar/VLan.o tmp/objs/Cedar/VLanUnix.o tmp/objs/Cedar/VLanWin32.o tmp/objs/Cedar/WaterMark.o tmp/objs/Cedar/WebUI.o tmp/objs/Cedar/WinUi.o tmp/objs/Cedar/Wpc.o

# Build Action
default:	build

build:	$(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/as/vpnserver.a \
bin/fuzzers/fuzzer-buf bin/fuzzers/standalone-buf \
bin/fuzzers/fuzzer-packetparse bin/fuzzers/standalone-packetparse \
bin/fuzzers/fuzzer-misc bin/fuzzers/standalone-misc \
bin/fuzzers/fuzzer-icmp bin/fuzzers/standalone-icmp \
bin/fuzzers/fuzzer-encrypt bin/fuzzers/standalone-encrypt \
bin/fuzzers/fuzzer-ipc bin/fuzzers/standalone-ipc \
bin/fuzzers/fuzzer-l2tp bin/fuzzers/standalone-l2tp \
bin/fuzzers/fuzzer-ovpn bin/fuzzers/standalone-ovpn \
bin/fuzzers/fuzzer-radius bin/fuzzers/standalone-radius \
bin/fuzzers/fuzzer-radius-eap bin/fuzzers/standalone-radius-eap \
bin/fuzzers/fuzzer-ppp bin/fuzzers/standalone-ppp \
bin/fuzzers/fuzzer-sstp bin/fuzzers/standalone-sstp

# Mayaqua Kernel Code
tmp/objs/Mayaqua/Cfg.o: src/Mayaqua/Cfg.c $(HEADERS_MAYAQUA)
	@mkdir -p tmp/
	@mkdir -p tmp/objs/
	@mkdir -p tmp/objs/Mayaqua/
	@mkdir -p tmp/objs/Cedar/
	@mkdir -p tmp/objs/fuzzers/
	@mkdir -p tmp/as/
	@mkdir -p bin/
	@mkdir -p bin/fuzzers/
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Cfg.c -o tmp/objs/Mayaqua/Cfg.o

tmp/objs/Mayaqua/Encrypt.o: src/Mayaqua/Encrypt.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Encrypt.c -o tmp/objs/Mayaqua/Encrypt.o

tmp/objs/Mayaqua/FileIO.o: src/Mayaqua/FileIO.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/FileIO.c -o tmp/objs/Mayaqua/FileIO.o

tmp/objs/Mayaqua/Internat.o: src/Mayaqua/Internat.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Internat.c -o tmp/objs/Mayaqua/Internat.o

tmp/objs/Mayaqua/Kernel.o: src/Mayaqua/Kernel.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Kernel.c -o tmp/objs/Mayaqua/Kernel.o

tmp/objs/Mayaqua/Mayaqua.o: src/Mayaqua/Mayaqua.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Mayaqua.c -o tmp/objs/Mayaqua/Mayaqua.o

tmp/objs/Mayaqua/Memory.o: src/Mayaqua/Memory.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Memory.c -o tmp/objs/Mayaqua/Memory.o

tmp/objs/Mayaqua/Microsoft.o: src/Mayaqua/Microsoft.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Microsoft.c -o tmp/objs/Mayaqua/Microsoft.o

tmp/objs/Mayaqua/Network.o: src/Mayaqua/Network.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Network.c -o tmp/objs/Mayaqua/Network.o

tmp/objs/Mayaqua/Object.o: src/Mayaqua/Object.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Object.c -o tmp/objs/Mayaqua/Object.o

tmp/objs/Mayaqua/OS.o: src/Mayaqua/OS.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/OS.c -o tmp/objs/Mayaqua/OS.o

tmp/objs/Mayaqua/Pack.o: src/Mayaqua/Pack.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Pack.c -o tmp/objs/Mayaqua/Pack.o

tmp/objs/Mayaqua/Secure.o: src/Mayaqua/Secure.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Secure.c -o tmp/objs/Mayaqua/Secure.o

tmp/objs/Mayaqua/Str.o: src/Mayaqua/Str.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Str.c -o tmp/objs/Mayaqua/Str.o

tmp/objs/Mayaqua/Table.o: src/Mayaqua/Table.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Table.c -o tmp/objs/Mayaqua/Table.o

tmp/objs/Mayaqua/TcpIp.o: src/Mayaqua/TcpIp.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/TcpIp.c -o tmp/objs/Mayaqua/TcpIp.o

tmp/objs/Mayaqua/Tick64.o: src/Mayaqua/Tick64.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Tick64.c -o tmp/objs/Mayaqua/Tick64.o

tmp/objs/Mayaqua/Tracking.o: src/Mayaqua/Tracking.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Tracking.c -o tmp/objs/Mayaqua/Tracking.o

tmp/objs/Mayaqua/Unix.o: src/Mayaqua/Unix.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Unix.c -o tmp/objs/Mayaqua/Unix.o

tmp/objs/Mayaqua/Win32.o: src/Mayaqua/Win32.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c src/Mayaqua/Win32.c -o tmp/objs/Mayaqua/Win32.o

# Cedar Communication Module Code
tmp/objs/Cedar/Account.o: src/Cedar/Account.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Account.c -o tmp/objs/Cedar/Account.o

tmp/objs/Cedar/Admin.o: src/Cedar/Admin.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Admin.c -o tmp/objs/Cedar/Admin.o

tmp/objs/Cedar/AzureClient.o: src/Cedar/AzureClient.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/AzureClient.c -o tmp/objs/Cedar/AzureClient.o

tmp/objs/Cedar/AzureServer.o: src/Cedar/AzureServer.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/AzureServer.c -o tmp/objs/Cedar/AzureServer.o

tmp/objs/Cedar/Bridge.o: src/Cedar/Bridge.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) src/Cedar/BridgeUnix.c
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Bridge.c -o tmp/objs/Cedar/Bridge.o

tmp/objs/Cedar/BridgeUnix.o: src/Cedar/BridgeUnix.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/BridgeUnix.c -o tmp/objs/Cedar/BridgeUnix.o

tmp/objs/Cedar/BridgeWin32.o: src/Cedar/BridgeWin32.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/BridgeWin32.c -o tmp/objs/Cedar/BridgeWin32.o

tmp/objs/Cedar/Cedar.o: src/Cedar/Cedar.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Cedar.c -o tmp/objs/Cedar/Cedar.o

tmp/objs/Cedar/CedarPch.o: src/Cedar/CedarPch.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/CedarPch.c -o tmp/objs/Cedar/CedarPch.o

tmp/objs/Cedar/Client.o: src/Cedar/Client.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Client.c -o tmp/objs/Cedar/Client.o

tmp/objs/Cedar/CM.o: src/Cedar/CM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/CM.c -o tmp/objs/Cedar/CM.o

tmp/objs/Cedar/Command.o: src/Cedar/Command.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Command.c -o tmp/objs/Cedar/Command.o

tmp/objs/Cedar/Connection.o: src/Cedar/Connection.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Connection.c -o tmp/objs/Cedar/Connection.o

tmp/objs/Cedar/Console.o: src/Cedar/Console.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Console.c -o tmp/objs/Cedar/Console.o

tmp/objs/Cedar/Database.o: src/Cedar/Database.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Database.c -o tmp/objs/Cedar/Database.o

tmp/objs/Cedar/DDNS.o: src/Cedar/DDNS.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/DDNS.c -o tmp/objs/Cedar/DDNS.o

tmp/objs/Cedar/EM.o: src/Cedar/EM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/EM.c -o tmp/objs/Cedar/EM.o

tmp/objs/Cedar/EtherLog.o: src/Cedar/EtherLog.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/EtherLog.c -o tmp/objs/Cedar/EtherLog.o

tmp/objs/Cedar/Hub.o: src/Cedar/Hub.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Hub.c -o tmp/objs/Cedar/Hub.o

tmp/objs/Cedar/Interop_OpenVPN.o: src/Cedar/Interop_OpenVPN.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Interop_OpenVPN.c -o tmp/objs/Cedar/Interop_OpenVPN.o

tmp/objs/Cedar/Interop_SSTP.o: src/Cedar/Interop_SSTP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Interop_SSTP.c -o tmp/objs/Cedar/Interop_SSTP.o

tmp/objs/Cedar/IPsec.o: src/Cedar/IPsec.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec.c -o tmp/objs/Cedar/IPsec.o

tmp/objs/Cedar/IPsec_EtherIP.o: src/Cedar/IPsec_EtherIP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_EtherIP.c -o tmp/objs/Cedar/IPsec_EtherIP.o

tmp/objs/Cedar/IPsec_IKE.o: src/Cedar/IPsec_IKE.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_IKE.c -o tmp/objs/Cedar/IPsec_IKE.o

tmp/objs/Cedar/IPsec_IkePacket.o: src/Cedar/IPsec_IkePacket.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_IkePacket.c -o tmp/objs/Cedar/IPsec_IkePacket.o

tmp/objs/Cedar/IPsec_IPC.o: src/Cedar/IPsec_IPC.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_IPC.c -o tmp/objs/Cedar/IPsec_IPC.o

tmp/objs/Cedar/IPsec_L2TP.o: src/Cedar/IPsec_L2TP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_L2TP.c -o tmp/objs/Cedar/IPsec_L2TP.o

tmp/objs/Cedar/IPsec_PPP.o: src/Cedar/IPsec_PPP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_PPP.c -o tmp/objs/Cedar/IPsec_PPP.o

tmp/objs/Cedar/IPsec_Win7.o: src/Cedar/IPsec_Win7.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/IPsec_Win7.c -o tmp/objs/Cedar/IPsec_Win7.o

tmp/objs/Cedar/Layer3.o: src/Cedar/Layer3.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Layer3.c -o tmp/objs/Cedar/Layer3.o

tmp/objs/Cedar/Link.o: src/Cedar/Link.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Link.c -o tmp/objs/Cedar/Link.o

tmp/objs/Cedar/Listener.o: src/Cedar/Listener.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Listener.c -o tmp/objs/Cedar/Listener.o

tmp/objs/Cedar/Logging.o: src/Cedar/Logging.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Logging.c -o tmp/objs/Cedar/Logging.o

tmp/objs/Cedar/Nat.o: src/Cedar/Nat.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Nat.c -o tmp/objs/Cedar/Nat.o

tmp/objs/Cedar/NativeStack.o: src/Cedar/NativeStack.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/NativeStack.c -o tmp/objs/Cedar/NativeStack.o

tmp/objs/Cedar/NM.o: src/Cedar/NM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/NM.c -o tmp/objs/Cedar/NM.o

tmp/objs/Cedar/NullLan.o: src/Cedar/NullLan.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/NullLan.c -o tmp/objs/Cedar/NullLan.o

tmp/objs/Cedar/Protocol.o: src/Cedar/Protocol.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Protocol.c -o tmp/objs/Cedar/Protocol.o

tmp/objs/Cedar/Radius.o: src/Cedar/Radius.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Radius.c -o tmp/objs/Cedar/Radius.o

tmp/objs/Cedar/Remote.o: src/Cedar/Remote.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Remote.c -o tmp/objs/Cedar/Remote.o

tmp/objs/Cedar/Sam.o: src/Cedar/Sam.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Sam.c -o tmp/objs/Cedar/Sam.o

tmp/objs/Cedar/SecureInfo.o: src/Cedar/SecureInfo.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SecureInfo.c -o tmp/objs/Cedar/SecureInfo.o

tmp/objs/Cedar/SecureNAT.o: src/Cedar/SecureNAT.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SecureNAT.c -o tmp/objs/Cedar/SecureNAT.o

tmp/objs/Cedar/SeLowUser.o: src/Cedar/SeLowUser.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SeLowUser.c -o tmp/objs/Cedar/SeLowUser.o

tmp/objs/Cedar/Server.o: src/Cedar/Server.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Server.c -o tmp/objs/Cedar/Server.o

tmp/objs/Cedar/Session.o: src/Cedar/Session.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Session.c -o tmp/objs/Cedar/Session.o

tmp/objs/Cedar/SM.o: src/Cedar/SM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SM.c -o tmp/objs/Cedar/SM.o

tmp/objs/Cedar/SW.o: src/Cedar/SW.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/SW.c -o tmp/objs/Cedar/SW.o

tmp/objs/Cedar/UdpAccel.o: src/Cedar/UdpAccel.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/UdpAccel.c -o tmp/objs/Cedar/UdpAccel.o

tmp/objs/Cedar/UT.o: src/Cedar/UT.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/UT.c -o tmp/objs/Cedar/UT.o

tmp/objs/Cedar/VG.o: src/Cedar/VG.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VG.c -o tmp/objs/Cedar/VG.o

tmp/objs/Cedar/Virtual.o: src/Cedar/Virtual.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Virtual.c -o tmp/objs/Cedar/Virtual.o

tmp/objs/Cedar/VLan.o: src/Cedar/VLan.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VLan.c -o tmp/objs/Cedar/VLan.o

tmp/objs/Cedar/VLanUnix.o: src/Cedar/VLanUnix.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VLanUnix.c -o tmp/objs/Cedar/VLanUnix.o

tmp/objs/Cedar/VLanWin32.o: src/Cedar/VLanWin32.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/VLanWin32.c -o tmp/objs/Cedar/VLanWin32.o

tmp/objs/Cedar/WaterMark.o: src/Cedar/WaterMark.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/WaterMark.c -o tmp/objs/Cedar/WaterMark.o

tmp/objs/Cedar/WebUI.o: src/Cedar/WebUI.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/WebUI.c -o tmp/objs/Cedar/WebUI.o

tmp/objs/Cedar/WinUi.o: src/Cedar/WinUi.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/WinUi.c -o tmp/objs/Cedar/WinUi.o

tmp/objs/Cedar/Wpc.o: src/Cedar/Wpc.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/Cedar/Wpc.c -o tmp/objs/Cedar/Wpc.o

tmp/as/vpnserver.a: tmp/objs/vpnserver.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/vpnserver.a
	ar r tmp/as/vpnserver.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/vpnserver.o
	ranlib tmp/as/vpnserver.a

tmp/objs/vpnserver.o: src/vpnserver/vpnserver.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c src/vpnserver/vpnserver.c -o tmp/objs/vpnserver.o

# Standalone runner

tmp/objs/fuzzers/standalone.o: src/fuzzers/standalone.c
		$(CC) $(OPTIONS_COMPILE) -c src/fuzzers/standalone.c -o tmp/objs/fuzzers/standalone.o

# Buf fuzzer
tmp/objs/fuzzers/buf.o: src/fuzzers/buf.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/buf.c -o tmp/objs/fuzzers/buf.o
bin/fuzzers/fuzzer-buf: tmp/as/vpnserver.a tmp/objs/fuzzers/buf.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/buf.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-buf
bin/fuzzers/standalone-buf: tmp/as/vpnserver.a tmp/objs/fuzzers/buf.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/buf.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-buf

# Packet parser fuzzer
tmp/objs/fuzzers/packetparse.o: src/fuzzers/packetparse.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/packetparse.c -o tmp/objs/fuzzers/packetparse.o
bin/fuzzers/fuzzer-packetparse: tmp/as/vpnserver.a tmp/objs/fuzzers/packetparse.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/packetparse.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-packetparse
bin/fuzzers/standalone-packetparse: tmp/as/vpnserver.a tmp/objs/fuzzers/packetparse.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/packetparse.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-packetparse

# Misc function fuzzer
tmp/objs/fuzzers/misc.o: src/fuzzers/misc.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/misc.c -o tmp/objs/fuzzers/misc.o
bin/fuzzers/fuzzer-misc: tmp/as/vpnserver.a tmp/objs/fuzzers/misc.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/misc.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-misc
bin/fuzzers/standalone-misc: tmp/as/vpnserver.a tmp/objs/fuzzers/misc.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/misc.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-misc

# ICMP fuzzer
tmp/objs/fuzzers/icmp.o: src/fuzzers/icmp.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/icmp.c -o tmp/objs/fuzzers/icmp.o
bin/fuzzers/fuzzer-icmp: tmp/as/vpnserver.a tmp/objs/fuzzers/icmp.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/icmp.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-icmp
bin/fuzzers/standalone-icmp: tmp/as/vpnserver.a tmp/objs/fuzzers/icmp.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/icmp.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-icmp

# Encrypt fuzzer
tmp/objs/fuzzers/encrypt.o: src/fuzzers/encrypt.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/encrypt.c -o tmp/objs/fuzzers/encrypt.o
bin/fuzzers/fuzzer-encrypt: tmp/as/vpnserver.a tmp/objs/fuzzers/encrypt.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/encrypt.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-encrypt
bin/fuzzers/standalone-encrypt: tmp/as/vpnserver.a tmp/objs/fuzzers/encrypt.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/encrypt.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-encrypt

# IPC fuzzer
tmp/objs/fuzzers/ipc.o: src/fuzzers/ipc.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/ipc.c -o tmp/objs/fuzzers/ipc.o
bin/fuzzers/fuzzer-ipc: tmp/as/vpnserver.a tmp/objs/fuzzers/ipc.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/ipc.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-ipc
bin/fuzzers/standalone-ipc: tmp/as/vpnserver.a tmp/objs/fuzzers/ipc.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/ipc.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-ipc

# L2TP fuzzer
tmp/objs/fuzzers/l2tp.o: src/fuzzers/l2tp.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/l2tp.c -o tmp/objs/fuzzers/l2tp.o
bin/fuzzers/fuzzer-l2tp: tmp/as/vpnserver.a tmp/objs/fuzzers/l2tp.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/l2tp.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-l2tp
bin/fuzzers/standalone-l2tp: tmp/as/vpnserver.a tmp/objs/fuzzers/l2tp.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/l2tp.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-l2tp

# OpenVPN fuzzer
tmp/objs/fuzzers/ovpn.o: src/fuzzers/ovpn.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/ovpn.c -o tmp/objs/fuzzers/ovpn.o
bin/fuzzers/fuzzer-ovpn: tmp/as/vpnserver.a tmp/objs/fuzzers/ovpn.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/ovpn.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-ovpn
bin/fuzzers/standalone-ovpn: tmp/as/vpnserver.a tmp/objs/fuzzers/ovpn.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/ovpn.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-ovpn

# RADIUS client fuzzer
tmp/objs/fuzzers/radius.o: src/fuzzers/radius.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/radius.c -o tmp/objs/fuzzers/radius.o
bin/fuzzers/fuzzer-radius: tmp/as/vpnserver.a tmp/objs/fuzzers/radius.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/radius.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-radius
bin/fuzzers/standalone-radius: tmp/as/vpnserver.a tmp/objs/fuzzers/radius.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/radius.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-radius

# RADIUS-EAP fuzzer
tmp/objs/fuzzers/radius-eap.o: src/fuzzers/radius-eap.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/radius-eap.c -o tmp/objs/fuzzers/radius-eap.o
bin/fuzzers/fuzzer-radius-eap: tmp/as/vpnserver.a tmp/objs/fuzzers/radius-eap.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/radius-eap.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-radius-eap
bin/fuzzers/standalone-radius-eap: tmp/as/vpnserver.a tmp/objs/fuzzers/radius-eap.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/radius-eap.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-radius-eap

# PPP fuzzer
tmp/objs/fuzzers/ppp.o: src/fuzzers/ppp.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/ppp.c -o tmp/objs/fuzzers/ppp.o
bin/fuzzers/fuzzer-ppp: tmp/as/vpnserver.a tmp/objs/fuzzers/ppp.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/ppp.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-ppp
bin/fuzzers/standalone-ppp: tmp/as/vpnserver.a tmp/objs/fuzzers/ppp.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/ppp.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-ppp

# SSTP fuzzer
tmp/objs/fuzzers/sstp.o: src/fuzzers/sstp.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -Wall -c src/fuzzers/sstp.c -o tmp/objs/fuzzers/sstp.o
bin/fuzzers/fuzzer-sstp: tmp/as/vpnserver.a tmp/objs/fuzzers/sstp.o
	$(CXX) $(OPTIONS_LINK)  tmp/objs/fuzzers/sstp.o $(LIBFUZZER_A) tmp/as/vpnserver.a -o bin/fuzzers/fuzzer-sstp
bin/fuzzers/standalone-sstp: tmp/as/vpnserver.a tmp/objs/fuzzers/sstp.o tmp/objs/fuzzers/standalone.o
		$(CXX) $(OPTIONS_LINK) tmp/objs/fuzzers/sstp.o tmp/objs/fuzzers/standalone.o tmp/as/vpnserver.a -o bin/fuzzers/standalone-sstp

# Clean
clean:
	-rm -f $(OBJECTS_MAYAQUA)
	-rm -f $(OBJECTS_CEDAR)
	-rm -f tmp/objs/vpnserver.o
	-rm -f tmp/as/vpnserver.a
	-rm -f bin/fuzzers/*
	-rm -f tmp/objs/fuzzers/*.o

# Help Strings
help:
	@echo "make [DEBUG=YES]"
	@echo "make clean"

