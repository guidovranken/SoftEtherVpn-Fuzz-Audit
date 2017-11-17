#include "Cedar/CedarPch.h"
#include "fuzzers/helper.h"

int LLVMFuzzerInitialize(int argc, char** argv)
{
    OSInit();
    InitCryptLibrary();
    InitInternational();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    CEDAR cedar;
    SOCK sock;

    FuzzingSetRecvRandom(1);
    FuzzingSetSendRandom(1);
    FuzzingSetRecvInput((unsigned char*)buf, len);

    memset(&cedar, 0, sizeof(cedar));
    memset(&sock, 0, sizeof(sock));
    memset(&sock.RemoteIP.addr, 0x50, 4);
    sock.RemotePort = 444;
    memset(&sock.LocalIP.addr, 0x40, 4);
    sock.LocalPort = 123;

    cedar.Server = (SERVER*)8;
    OvsPerformTcpServer(&cedar, &sock);
    return 0;
}
