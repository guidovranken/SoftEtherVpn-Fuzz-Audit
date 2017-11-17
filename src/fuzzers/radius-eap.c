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
    EAP_CLIENT eap;
    unsigned char client_response[24];
    unsigned char client_challenge[16];
    memset(&eap, 0, sizeof(eap));

    if ( len < sizeof(client_response) ) {
        return 0;
    }
    memcpy(client_response, buf, sizeof(client_response));
    buf += sizeof(client_response);
    len -= sizeof(client_response);

    if ( len < sizeof(client_challenge) ) {
        return 0;
    }
    memcpy(client_challenge, buf, sizeof(client_challenge));
    buf += sizeof(client_challenge);
    len -= sizeof(client_challenge);

    FuzzingSetRecvRandom(1);
    FuzzingSetSendRandom(1);
    FuzzingSetRecvInput((unsigned char*)buf, len);

    eap.GiveupTimeout = 1000;
    EapClientSendMsChapv2AuthClientResponse(&eap, client_response, client_challenge);

    return 0;
}
