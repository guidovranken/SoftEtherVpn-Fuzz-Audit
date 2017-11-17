#include "Cedar/CedarPch.h"
#include "fuzzers/helper.h"

void FreeL2TPPacket(L2TP_PACKET *p);

int LLVMFuzzerInitialize(int argc, char** argv)
{
    OSInit();
    return 0;
}

static void test_Radius(const uint8_t* buf, size_t len)
{
    unsigned char* buf2 = clone(buf, len);
    RADIUS_PACKET* pkt = ParseRadiusPacket(buf2, len);
#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)pkt, sizeof(*pkt));
#endif
    FreeRadiusPacket(pkt);
    free(buf2);
}

static void test_Sstp(const uint8_t* buf, size_t len)
{
    unsigned char* buf2 = clone(buf, len);
    SSTP_PACKET* pkt = SstpParsePacket(buf2, len);
#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)pkt, sizeof(*pkt));
#endif
    SstpFreePacket(pkt);
    free(buf2);
}

static void test_Ovs(const uint8_t* buf, size_t len)
{
    unsigned char* buf2 = clone(buf, len);
    OPENVPN_PACKET* pkt = OvsParsePacket(buf2, len);
#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)pkt, sizeof(*pkt));
#endif
    OvsFreePacket(pkt);
    free(buf2);
}

static void test_PPP(const uint8_t* buf, size_t len)
{
    unsigned char* buf2 = clone(buf, len);
    PPP_PACKET* pkt = ParsePPPPacket(buf2, len);
#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)pkt, sizeof(*pkt));
#endif
    FreePPPPacket(pkt);
    free(buf2);
}

static UDPPACKET* parse_UDP(const uint8_t* buf, size_t len, void** freebuf)
{
    unsigned char* buf2 = NULL;
    UDPPACKET* udppacket = NULL;

    struct {
        IP src, dst;
        UINT src_port, dst_port;
    } UDPParams;

    /* Extract source IP from input */
    if ( len < sizeof(UDPParams) ) {
        return NULL;
    }
    memcpy(&UDPParams, buf, sizeof(UDPParams));
    buf += sizeof(UDPParams);
    len -= sizeof(UDPParams);

    /* Use the remainder of the input as packet data */
    buf2 = clone(buf, len);

    udppacket = NewUdpPacket(&UDPParams.src, UDPParams.src_port, &UDPParams.dst, UDPParams.dst_port, buf2, len);

    *freebuf = buf2;

#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)udppacket, sizeof(*udppacket));
#endif
    return udppacket;
}

static void test_L2TP(const uint8_t* buf, size_t len)
{
    void* freebuf = NULL;
    UDPPACKET* udppacket = parse_UDP(buf, len, &freebuf);
    L2TP_PACKET* pkt = ParseL2TPPacket(udppacket);
#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)pkt, sizeof(*pkt));
#endif
    FreeL2TPPacket(pkt);
    Free(udppacket);
    free(freebuf);
}

static void test_IKE(const uint8_t* buf, size_t len)
{
    void* freebuf = NULL;
    UDPPACKET* udppacket = parse_UDP(buf, len, &freebuf);
    IKE_PACKET* pkt = ParseIKEPacketHeader(udppacket);
#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)pkt, sizeof(*pkt));
#endif
    IkeFree(pkt);
    Free(udppacket);
    free(freebuf);
}

static void test_DNS(const uint8_t* buf, size_t len)
{
    UINT parameters[4];
    unsigned char* buf2 = NULL;

    if ( len < sizeof(parameters) ) {
        return;
    }
    memcpy(parameters, buf, sizeof(parameters));
    buf += sizeof(parameters);
    len -= sizeof(parameters);

    buf2 = clone(buf, len);
    ParseDnsPacket(
            (void*)8,
            parameters[0],
            parameters[1],
            parameters[2],
            parameters[3],
            buf2,
            len);
    free(buf2);
}

static void test_DNSResponse(const uint8_t* buf, size_t len)
{
    unsigned char* buf2 = clone(buf, len);
    IP ip;
    memset(&ip, 0, sizeof(ip));
    NnParseDnsResponsePacket(buf2, len, &ip);
#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)&ip, sizeof(ip));
#endif
    free(buf2);
}

static PKT* parse_Packet(const uint8_t* buf, size_t len, void** freebuf)
{
    PKT* pkt = NULL;
    unsigned char* buf2 = NULL;
    struct {
        unsigned char no_l3;
        unsigned char bridge_id_as_mac_address;
        unsigned char no_http;
        unsigned char correct_checksum;
        UINT vlan_type_id;
    } PacketParams;

    if ( len < sizeof(PacketParams) ) {
        return NULL;
    }

    memcpy(&PacketParams, buf, sizeof(PacketParams));
    buf += sizeof(PacketParams);
    len -= sizeof(PacketParams);

    buf2 = clone(buf, len);

    pkt = ParsePacketEx4(
            buf2,
            len,
            PacketParams.no_l3 % 2 ? true : false,
            PacketParams.vlan_type_id,
            PacketParams.bridge_id_as_mac_address % 2 ? true : false,
            PacketParams.no_http % 2 ? true : false,
            PacketParams.correct_checksum % 2 ? true : false);

    *freebuf = buf2;

#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)pkt, sizeof(*pkt));
#endif

    return pkt;
}

static void test_DHCPv4(const uint8_t* buf, size_t len)
{
    void* freebuf = NULL;
    PKT* pkt = parse_Packet(buf, len, &freebuf);
    DHCPV4_DATA* dhcp_pkt = ParseDHCPv4Data(pkt);
#ifdef FUZZING_MSAN
    test_MSAN((unsigned char*)dhcp_pkt, sizeof(*dhcp_pkt));
#endif
    FreeDHCPv4Data(dhcp_pkt);
    FreePacket(pkt);
    free(freebuf);
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    test_Radius(buf, len);
    test_Sstp(buf, len);
    test_Ovs(buf, len);
    test_PPP(buf, len);
    test_L2TP(buf, len);
    test_IKE(buf, len);
    test_DNS(buf, len);
    test_DNSResponse(buf, len);
    test_DHCPv4(buf, len);
    return 0;
}
