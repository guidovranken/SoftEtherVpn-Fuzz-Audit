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
    IPC* ipc = NULL;
    IP client_ip, server_ip;
    CEDAR* cedar = calloc(1, sizeof(CEDAR));

    FuzzingSetRecvRandom(0);
    FuzzingSetRecvInput((unsigned char*)buf, len);

    memset(&client_ip, 0, sizeof(client_ip));
    memset(&server_ip, 0, sizeof(server_ip));

    ipc = NewIPC(
            cedar,
            NULL, /* client_name, auto-set if NULL */
            "postfix",
            "hubname",
            "username",
            "password",
            NULL, /* error_code */
            &client_ip,
            0, /* client_port */
            &server_ip,
            0, /* server_port */
            "client-hostname",
            NULL, /* crypt_name */
            false, /* bridge_mode */
            1000, /* mss */
            NULL /* eap_client */
    );

    if ( ipc ) {
        DHCP_OPTION_LIST cao;
        memset(&cao, 0, sizeof(cao));
        FuzzingSetRecvRandom(1);
        IPCDhcpAllocateIPEx(ipc, &cao, NULL, true);
    }
	FreeIPC(ipc);

    free(cedar);

    return 0;
}
