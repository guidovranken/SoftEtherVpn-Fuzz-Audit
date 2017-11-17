#include "Cedar/CedarPch.h"
#include "fuzzers/helper.h"

int LLVMFuzzerInitialize(int argc, char** argv)
{
    OSInit();
    InitInternational();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    CONNECTION c;
    SOCK s;
    CEDAR cedar;

    memset(&c, 0, sizeof(c));
    memset(&s, 0, sizeof(s));
    memset(&cedar, 0, sizeof(cedar));
    FuzzingSetRecvRandom(1);
    FuzzingSetRecvInput((unsigned char*)buf, len);
    c.FirstSock = &s;

    cedar.ref = NewRef();
    c.Cedar = &cedar;

    AcceptSstp(&c);

    Release(cedar.ref);

    return 0;
}
