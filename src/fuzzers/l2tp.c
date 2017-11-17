#include "Cedar/CedarPch.h"
#include "fuzzers/helper.h"

int LLVMFuzzerInitialize(int argc, char** argv)
{
    OSInit();
    return 0;
}

static void preprocess_packet(L2TP_SERVER* l2tp, uint8_t* buf, size_t len)
{
    UDPPACKET* udppacket = NULL;
    uint8_t* data = NULL;
    struct {
        IP src, dst;
        UINT src_port;
    } params;

    if ( len < sizeof(params) ) {
        return;
    }
    memcpy(&params, buf, sizeof(params));
    buf += sizeof(params);
    len -= sizeof(params);
    /*params.src_port = 1000001;*/

    /* Use the remainder of the input as packet data */
    data = clone(buf, len);

    udppacket = NewUdpPacket(&params.src, params.src_port, &params.dst, IPSEC_PORT_L2TP, data, len);

    {
        IPSEC_SERVER s;
        memset(&s, 0, sizeof(s));
        s.L2TP = l2tp;
        IPsecProcPacket(&s, udppacket);
	    L2TPProcessInterrupts(l2tp);
    }

    Free(udppacket);
    free(data);
    return;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    L2TP_SERVER* l2tp = NULL;
    CEDAR cedar;
    memset(&cedar, 0, sizeof(cedar));

    l2tp  = NewL2TPServer(&cedar);
    l2tp->Interrupts = NewInterruptManager();

    while ( 1 )
    {
        uint16_t packetlen;
        uint8_t* packet = NULL;
        if ( len < sizeof(packetlen) ) {
            goto end;
        }
        memcpy(&packetlen, buf, sizeof(packetlen));
        buf += sizeof(packetlen);
        len -= sizeof(packetlen);

        if ( packetlen > len ) {
            goto end;
        }
        packet = clone(buf, packetlen);
        buf += packetlen;
        len -= packetlen;

        preprocess_packet(l2tp, packet, packetlen);
        free(packet);
    }

end:
    FreeInterruptManager(l2tp->Interrupts);
	StopL2TPServer(l2tp, false);
    FreeL2TPServer(l2tp);

    return 0;
}
