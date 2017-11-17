#include "Cedar/CedarPch.h"
#include "fuzzers/helper.h"

int LLVMFuzzerInitialize(int *argc, char*** argv)
{
    OSInit();
    InitInternational();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    CEDAR cedar;
    PPP_SESSION* p;
	SOCK *s;
    SOCK dummysocket;
    struct {
        IP client_ip;
        IP server_ip;
        UINT client_port;
        UINT server_port;
    } ppp_parameters;


    if ( len < sizeof(ppp_parameters) ) {
        return 0;
    }
    memcpy(&ppp_parameters, buf, sizeof(ppp_parameters));
    buf += sizeof(ppp_parameters);
    len -= sizeof(ppp_parameters);

    FuzzingSetRecvRandom(1);
    FuzzingSetSendRandom(1);
    FuzzingSetRecvInput((unsigned char*)buf, len);

    memset(&dummysocket, 0, sizeof(dummysocket));
    s = &dummysocket;

	p = ZeroMalloc(sizeof(PPP_SESSION));
    memset(&cedar, 0, sizeof(cedar));
	StrCpy(p->Postfix, sizeof(p->Postfix), "postfix");
	StrCpy(p->ClientSoftwareName, sizeof(p->ClientSoftwareName), "PPP VPN Client");
	p->EnableMSCHAPv2 = true;
	p->AuthProtocol = PPP_PROTOCOL_PAP;
	p->MsChapV2_ErrorCode = 691;
	p->AdjustMss = 0;
	StrCpy(p->CryptName, sizeof(p->CryptName), "");

	Copy(&p->ClientIP, &ppp_parameters.client_ip, sizeof(IP));
	p->ClientPort = ppp_parameters.client_port;

	Copy(&p->ServerIP, &ppp_parameters.server_ip, sizeof(IP));
	p->ServerPort = ppp_parameters.server_port;

    IPToStr(p->ClientHostname, sizeof(p->ClientHostname), &ppp_parameters.client_ip);
	p->FlushList = NewTubeFlushList();

	p->Cedar = &cedar;
	NewTubePair(&p->TubeSend, &p->TubeRecv, 0);

    PPPThread((THREAD*)8, (void*)p);
    return 0;
}
