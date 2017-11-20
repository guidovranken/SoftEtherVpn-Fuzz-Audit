# Preface

This document accompanies the code modifications and additions that have been the result of a 80 hour fuzzing-based code audit commissioned by the Max Planck Institute for Molecular Genetics in September 2017. It serves to provide on an overview of the changes made to the original SoftEther VPN source code, and to provide instructions to those who wish to run the fuzzer suite. 

Guido Vranken

https://guidovranken.wordpress.com/

guidovranken@gmail.com

# Overview of modifications


All changes made to the original source code are enclosed in compile-time conditions, eg.:

```c
#ifndef FUZZING
/* Original code */
#else
/* Code specific to fuzzing mode */
#endif
```

At all times you want the fuzzer cover as much code as possible, but at the same time refrain from accessing the real network, real files on disk and executing external programs. The fuzzing process benefits from being as deterministic as possible, because fuzzer's input mutation strategy is optimized for this, and it allows the analyst to easily reproduce crashes. What's more, if not all network access would have been artificially cut off by my modifications, there is a chance that the network is flooded with random packets. Similarly, if file system access and execution of external programs is not curtailed, files may be created and deleted at random, leading to system instability, and even in a sand-boxed environment (such as a virtual machine) this would obstruct the aim of this project.

Most of the edits to the original source code are done for the purpose of virtualizing (making virtual) the environment in which SoftEther VPN normally operates, so that IO-independent logic such as packet parsing is fuzzed as normal, but IO and system facility access is emulated, generating data and status codes as real IO would.

SoftEther VPN being an application for accessing and manipulating computer networks, the ```Recv()``` function, where data from the network enters the application, is very essential. Care has been taken that in fuzzing mode, the ways in which it can behave is the same as in a real networked environment. This includes returning the special ```SOCK_LATER``` value to the caller to indicate that no data is available yet, as well as filling only a portion of the output buffer.

```TubeSendEx2()``` is modified to call ```Send()``` in fuzzing mode.
```SslBioSync()``` calls ```Send()``` instead of OpenSSL's ```BIO_write()```, and ```Recv()``` instead of ```BIO_read()```.
```SendToEx()```, ```Send6ToEx()```, ```RecvFrom()```, ```RecvFrom6``` are also modifed to directly rely on ```Recv()``` and ```Send()```.

Similarly, the ```Send()``` function is interesting from a security perspective. If MemorySanitizer is enabled, the buffer that the caller wants to send is tested for containing uninitialized memory (using the ```test_MSAN()``` function, see below). Sending uninitialized data may be an important security problem, as this data may contain remnants of key material or other sensitive data. Furthermore, just like in the ```Recv()``` function, the ```Send()``` function in fuzzing mode may report to the caller that it only sent a portion of the buffer, or report a ```SOCK_LATER```.

Some static codes, such as the OpenVPN ping signature and the DHCP "magic cookie" value, have been changed to all zeros in fuzzing mode, for the benefit of easier detection by the fuzzer:

```c
 120 // Ping signature of the OpenVPN protocol
 121 #ifndef FUZZING
 122 static UCHAR ping_signature[] =
 123 {
 124     0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
 125     0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
 126 };
 127 #else
 128 /* Make the ping signature easier to detect by the fuzzer */
 129 static UCHAR ping_signature[] =
 130 {
 131     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 132     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 133 };
 134 #endif
```

```c
 892 // Parse the DHCPv4 packet
 893 DHCPV4_DATA *ParseDHCPv4Data(PKT *pkt)
 894 {
 895     DHCPV4_DATA *d;
 896     UCHAR *data;
 897     UINT size;
 898 #ifndef FUZZING
 899     UINT magic_cookie = Endian32(DHCP_MAGIC_COOKIE);
 900 #else
 901     UINT magic_cookie = Endian32(0);
 902 #endif
```

The return value of ```IpChecksum()``` in ```src/Mayaqua/TcpIp.c```, which is a 16 bit value, is truncated to the retain only the last 2 bits:

```c
3362 #ifndef FUZZING
3363     return answer;
3364 #else
3365     /* Make it easier for the fuzzer to find checksum matches */
3366     return answer & 0x3;
3367 #endif
3368 }
```

This makes it easier for the fuzzer to find IP checksum matches, as the value domain is reduced from 65536 to 4.

The Tick64 function, which normally returns the current system clock value, is culled from the fuzzer input:

```c
186 // Get the Tick value
187 UINT64 Tick64()
188 {
189 #ifndef FUZZING
...
...
205 #else /* FUZZING */
206     /* This is the "backup" value if Recv fails due to insufficient input data */
207     UINT64 ret = 0x1111111111111111;
208     Recv((SOCK*)8, &ret, sizeof(ret), false);
209     /* TODO variable return value */
210     return ret;
211 #endif
212 }
```

In fuzzing mode, the ```Recv()``` function does not actually receive something from a socket, but extracts data from the fuzzer input. Hence, it can be conveniently be used to extract a value for the ```Tick64()``` function. If the fuzzer input has already been exhausted, the default value 0x1111111111111111 is returned. This is an arbitrarily chosen non-zero value.

Because in fuzzing mode the ```Tick64()``` has no relationship with linear, physical time whatsoever, but rather is extracted from the fuzzer input, a situation may occur in which a second call returns a lower value than a first call. This would normally indicate having gone backwards in time, something that will never happen with a real system clock, and understandably there might be logic in SoftEther VPN that is not prepared for this, possibly resulting in an infinite loop or other strange behavior. Nothing of such nature has been observed throughout the course of my audit, but future extensions to the current fuzzing suite will have to keep this anomaly in mind.

The fuzzing version of ```Rand()``` is grounded in equivalent logic:

```c
4065 // Random number generation
4066 void Rand(void *buf, UINT size)
4067 {
4068     // Validate arguments
4069     if (buf == NULL || size == 0)
4070     {
4071         return;
4072     }
4073 #ifndef FUZZING
4074     RAND_bytes(buf, size);
4075 #else
4076     /* This is the "backup" value if Recv fails due to insufficient input data */
4077     memset(buf, 0x11, size);
4078 
4079     Recv((SOCK*)8, buf, size, false);
4080 #endif
4081 }
```

As noted before, determinism is important in a fuzzing environment. As such, the OpenSSL PRNG is not desirable here because its internal seeding procedure intentionally relies on variable sources, such as ```/dev/urandom```, the system clock and contents of uninitialized memory.


```RecvFrom()``` and ```RecvFrom6``` will normally set the source address and source port of the packet that is receives.

```c
11845 UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
```

In fuzzing mode these are also defined by the fuzzer input:

```c
11943     memset(src_addr, 0x11, sizeof(IP));
11944     memset(src_port, 0x11, sizeof(UINT));
11945     Recv((SOCK*)8, src_addr, sizeof(IP), false);
11946     Recv((SOCK*)8, src_port, sizeof(UINT), false);
11947     return Recv(sock, data, size, false);
```

The L2TP code deals extensively with certain values that it expects to be retained across packets (such as tunnel ID, session ID, packet types expected to be a special value). Here, I've artifically reduced the value range:

```c
 667         // L2TP
 668         ret->TunnelId = READ_USHORT(buf);
 669 #ifdef FUZZING
 670         ret->TunnelId %= 20;
 671 #endif
 672         buf += 2;
 673         size -= 2;
 674
 675         ret->SessionId = READ_USHORT(buf);
 676 #ifdef FUZZING
 677         ret->SessionId %= 20;
 678 #endif
 679         buf += 2;
 680         size -= 2;
```

By performing modulo on the original value, the value domain is reduced from 0..65536 to 0..19. This makes it much more probaly that the fuzzer can match two or more similar packets.

Similarly, I've artifically increased the odds of generating a packet with a valid packet type.

```c
 805 #ifdef FUZZING
 806             if ( a.Type > 71 )
 807             {
 808                 unsigned char validtypes[] = {0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 14, 15, 46, 60, 61, 62, 63, 64, 68, 71};
 809                 a.Type %= sizeof(validtypes);
 810                 a.Type = validtypes[a.Type];
 811             }
 812 #endif

```

The numbers in ```validtypes``` have been extracted from ```src/Cedar/IPsec_L2TP.h```:

```c
172 // AVP value
173 #define L2TP_AVP_TYPE_MESSAGE_TYPE      0       // Message Type
174 #define L2TP_AVP_TYPE_RESULT_CODE       1       // Result Code
175 #define L2TP_AVP_TYPE_PROTOCOL_VERSION  2       // Protocol Version
176 #define L2TP_AVP_TYPE_FRAME_CAP         3       // Framing Capabilities
177 #define L2TP_AVP_TYPE_BEARER_CAP        4       // Bearer Capabilities
178 #define L2TP_AVP_TYPE_TIE_BREAKER       5       // Tie Breaker
179 #define L2TP_AVP_TYPE_HOST_NAME         7       // Host Name
180 #define L2TP_AVP_TYPE_VENDOR_NAME       8       // Vendor Name
181 #define L2TP_AVP_TYPE_ASSIGNED_TUNNEL   9       // Assigned Tunnel
182 #define L2TP_AVP_TYPE_RECV_WINDOW_SIZE  10      // Receive Window Size
183 #define L2TP_AVP_TYPE_ASSIGNED_SESSION  14      // Assigned Session ID
184 #define L2TP_AVP_TYPE_CALL_SERIAL       15      // Call Serial Number
185 #define L2TP_AVP_TYPE_PPP_DISCONNECT_CAUSE  46  // PPP Disconnect Cause Code
186 #define L2TP_AVP_TYPE_V3_ROUTER_ID      60      // Router ID
187 #define L2TP_AVP_TYPE_V3_TUNNEL_ID      61      // Assigned Control Connection ID
188 #define L2TP_AVP_TYPE_V3_PW_CAP_LIST    62      // Pseudowire Capabilities List
189 #define L2TP_AVP_TYPE_V3_SESSION_ID_LOCAL   63  // Local Session ID
190 #define L2TP_AVP_TYPE_V3_SESSION_ID_REMOTE  64  // Remote Session ID
191 #define L2TP_AVP_TYPE_V3_PW_TYPE        68      // Pseudowire Type
192 #define L2TP_AVP_TYPE_V3_CIRCUIT_STATUS 71

```

Sometimes the code expects input stored at an earlier stage to be a of a specific length, like ```sizeof(UINT)```. I've relaxed the conditions for this:

```c
 870         L2TP_AVP *a = GetAVPValue(ret, L2TP_AVP_TYPE_V3_SESSION_ID_REMOTE);
 871 #ifndef FUZZING
 872         if (a != NULL && a->DataSize == sizeof(UINT))
 873 #else
 874         if (a != NULL && a->DataSize >= sizeof(UINT))
 875 #endif
 876         {
 877             ret->SessionId = READ_UINT(a->Data);
 878         }
```

Several more examples of this can be found in ```src/Cedar/IPsec_L2TP.c```.

In several places, pointers are set to the dummy value ```8```, such as in ```NewIPCAsync()``` in ```src/Cedar/IPsec_IPC.c```:

```c
 201 #ifndef FUZZING
 202     a->Thread = NewThread(IPCAsyncThreadProc, a);
 203 #else
 ...
 ...
 207     a->Ipc = (IPC*)8;
 ...
 ...
 209 #endif
```

The value ```8``` is chosen because:
* It can not be NULL (0) because this would indicate to the rest of the code that the pointer is uninitialized.
* It is a 64-bit (8 bytes) aligned pointer -- this prevents ```UndefinedBehaviorSanitizer``` detecting misalignments.
* The pointer ```8``` is always an invalid pointer. Hence, if this pointer is derefenced, it will reliably trigger a crash.

At other places in the code where this pointer is accessed, it is intercepted and the code depending on its value is made to behave as if the pointer were initialized normally:

```
 902 // Get whether the IPC is connected
 903 bool IsIPCConnected(IPC *ipc)
 904 {
 905     // Validate arguments
 906     if (ipc == NULL)
 907     {
 908         return false;
 909     }
 910 #ifdef FUZZING
 911     if (ipc == (IPC*)8)
 912     {
 913         return true;
 914     }
 915 #endif
 ...
 ...
```

# The fuzzers

The fuzzers are located in the ```src/fuzzers``` directory.

## Buffer fuzzer (buf.c)

This fuzzes various functions that operate on buffers (as in, SoftEther VPN's BUF struct). This is done in a "serialized" fashion, where the sequence of the distinct operations if defined by the fuzzer input.

One sequence might be:

* Create a buffer with ```NewBufFromMemory()```
* Call ```AdjustBufSize()``` on the buffer
* Call ```SeekBufToBegin()``` on the buffer

whereas another sequence might be:

* Create a buffer with ```NewBuf()```
* Call ```SeekBuf()``` on the buffer
* Call ```ReadBufRemainSize()``` on the buffer

This strategy ensures that if a bug depends on a distict sequence of buffer operations, it will eventually be discovered by the fuzzer.

If ```MemorySanitizer``` is enabled, the final contents of the buffer is tested for containing uninitialized memory.

## Packet parser fuzzer (packetparse.c)

Parses these types of packets:

* RADIUS
* SSTP
* OpenVPN
* PPP
* L2TP
* IKE
* DNS
* DNS response
* DHCP v4
* UDP packet
* General packet. This includes ARP, IPv4, IPv6, ICMP, TCP, UDP.

In MemorySanitizer mode, the packet that is produced from the input data, is tested for containing uninitialized data.

## RADIUS client fuzzer (radius.c)

This fuzzes the ```RadiusLogin()``` function in ```src/Cedar/Radius.c```.

## RADIUS-EAP fuzzer (radius-eap.c)

This fuzzes the ```EapClientSendMsChapv2AuthClientResponse()``` function in ```src/Cedar/Radius.c```.

## OpenVPN (ovpn.c)

This fuzzes the ```OvsPerformTcpServer()``` function in ```src/Cedar/Interop_OpenVPN.c```.

## SSTP (sstp.c)

This fuzzes the ```AcceptSstp()``` function in ```src/Cedar/Interop_SSTP.c```.

The creation of a separate PPP thread has been disabled for fuzzing mode in ```src/Cedar/Interop_SSTP.c```. Spawning threads in a fuzzing environment is problematic primarily because the determinism of the operation is lost, which is undesirable for reasons noted elsewhere. It would have been possible to work around this by editing all thread-focused code into single-thread logic, but in this case it would not have provided any benefit, because:
* The PPP module is fuzzed by a separate fuzzer, and any existing bugs this specific module are expected to emerge from running it.
* The SSTP code has been altered to "receive" data from the fuzzing input instead of from the PPP thread, thereby making its behavior analogous with a threaded form.

## Miscellaneous functions fuzzer (misc.c)

This fuzzes the following functions:

* ParseUrl
* IPToUniStr
* IPToUniStr32
* IPToStr
* StrToBin
* BinToStr
* CopyBinToStr
* IsNum
* NormalizeCrlf
* ParseToken
* StartWith
* EndWith
* ToInt64
* ToStr64
* IsEmptyString
* MacToStr
* StrToIP
* UniStrToIP32
* IPToInAddr
* IPToInAddr6
* InAddrToIP
* InAddrToIP6

In addition to fuzzing these functions, their return data is tested for containing uninitialized memory with the ```test_MSAN()``` helper function.

## ICMP fuzzer (icmp.c)

This fuzzes the following ICMP-oriented functions:

* IcmpParseResult
* BuildIPv6
* IcmpEchoSend
* IsDhcpPacketForSpecificMac
* AdjustTcpMssL2
* VLanRemoveTag
* BuildICMPv6
* BuildICMPv6NeighborSoliciation

Before running any of these functions, the fuzzer input data is split up into two equal parts: one to serve as input to the function directly, and the other to serve as a network data buffer, from which any function can "receive" data via ```Recv()``` or similar functions.

## L2TP fuzzer (l2tp.c)

This fuzzes the code in ```src/Cedar/IPsec_L2TP.c```, through the ```IPsecProcPacket()``` and ```L2TPProcessInterrupts()``` functions.


## PPP fuzzer (ppp.c)

This fuzzes the ```PPPThread()``` function in ```src/Cedar/IPsec_PPP.c```.

The original code relies on creating an ```IPC``` instance. In fuzzing mode, a "minimized" version of ```NewIPC()```, ```FuzzingNewIpc()```that is implemented in ```src/Cedar/IPsec_IPC.c```, is called. This creates an ```IPC``` instance without requiring the fuzzing to traverse the complex HTTP interaction with the peer. The original ```NewIPC()``` logic can be tested with the IPC fuzzer.c.

## IPC fuzzer (ipc.c)

This fuzzes the ```NewIPC()``` function in ```src/Cedar/IPsec_IPC.c```.

# Compiling

Copy ```src/makefiles/linux_64bit_fuzzing.mak``` to the project root directory, eg.:

```
cp src/makefiles/linux_64bit_fuzzing.mak Makefile
```

* To enable AddressSanitzer and UndefinedBehaviorSanitizer , compile without any arguments, eg. ```make```.
* To enable MemorySanitizer, compile with ```make SAN=MEM```.
* To disable all sanitizers, compile with ```make SAN=NO```. This makes execution faster, but does not detect all memory errors, only the most severe (such as null pointer dereferences).


These options are mutually exclusive; they can not be used together.

Before compiling with a different option, always run ```make clean```.

For building, the following programs are required:

* A recent version of Clang
* libFuzzer.a, placed in the root directory of the project

The following instructions have partially been taken from the [OpenSSL guide](https://github.com/openssl/openssl/blob/master/fuzz/README.md) to obtain these programs.

A recent version of Clang can be obtained to these commands:

```sh
$ sudo apt-get install git
$ mkdir git-work
$ git clone https://chromium.googlesource.com/chromium/src/tools/clang
$ clang/scripts/update.py
```

Be sure that its binaries are in your PATH:

```sh
$ PATH=~/third_party/llvm-build/Release+Asserts/bin/:$PATH
```

To obtain libFuzzer:

```sh
$ sudo apt-get install subversion
$ mkdir svn-work
$ cd svn-work
$ svn co https://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer Fuzzer
$ cd Fuzzer
$ clang++ -c -g -O2 -std=c++11 *.cpp
$ ar r libFuzzer.a *.o
$ ranlib libFuzzer.a
```

# Running

The fuzzer binaries will be located in ```bin/fuzzers``` after compilation.
If the fuzzers were not compiled with ```SAN=MSAN```, they can be run with

```sh
bin/fuzzers/fuzzer-<name> -use_value_profile=1 <corpus_directory>
```

So to run the buffer fuzzer and have it operate on the working directory ```corpus-buf```, do:

```sh
bin/fuzzers/fuzzer-buf -use_value_profile=1 corpus-buf/
```

The ```-use_value_profile=1``` argument is not strictly necessary, but it almost always leads to faster discovery of new code paths.

To run multiple threads of the fuzzer, the argument ```-jobs=N``` may be supplied, where ```N``` is the number of concurrent threads.

## MemorySanitizer


```MemorySanitizer``` is a special sanitizer to detect the usage of uninitialized memory. This is very valuable because in theory it can detect problems that might lead to remote code execution or other unexpected behavior whereas ```AddressSanitizer``` and ```UndefinedBehaviorSanitizer``` are not equipped to detect this particular anomaly.

For internal technical reasons, by default the fuzzers can not run with ```MemorySanitizer``` enabled (eg. if the project was compiled with ```make SAN=MSAN```). If this is nonetheless required by the analyst, libc must be manually re-compiled with ```MemorySanitizer``` enabled. Otherwise, the following workaround can be used.

Once a set of inputs has been generated with the fuzzer in non-```MemorySanitizer``` mode, the "standalone" binaries in ```bin/fuzzers``` can be used to run the ```MemorySanitizer```-enabled binaries against these individual inputs:

```sh
find <corpus_directory> -type f -exec bin/fuzzers/standalone-<name> {} \;
```

