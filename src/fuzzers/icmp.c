#include "Cedar/CedarPch.h"
#include "fuzzers/helper.h"

int LLVMFuzzerInitialize(int argc, char** argv)
{
    OSInit();
    InitInternational();
    return 0;
}

static void test_IcmpParseResult(const uint8_t* buf, size_t len)
{
    unsigned char* buf2;
    struct {
        IP dest_ip;
        USHORT src_id, src_seqno;
    } params;

	if ( len < sizeof(params) ) {
		return;
	}
	memcpy(&params, buf, sizeof(params));
	buf += sizeof(params);
	len -= sizeof(params);

    buf2 = clone(buf, len);
	IcmpFreeResult(IcmpParseResult(
                &params.dest_ip,
                params.src_id,
                params.src_seqno,
                buf2,
                len));
    free(buf2);
}

static void test_IcmpEchoSend(const uint8_t* buf, size_t len)
{
    unsigned char* buf2;
    struct {
        IP dest_ip;
        USHORT ttl, timeout;
        USHORT mod;
        size_t size2;
    } params;

	if ( len < sizeof(params) ) {
		return;
	}
	memcpy(&params, buf, sizeof(params));
	buf += sizeof(params);
	len -= sizeof(params);

    buf2 = clone(buf, len);
	IcmpFreeResult(IcmpEchoSend(
                &params.dest_ip,
                params.ttl,
                buf2,
                len,
                params.timeout));
    free(buf2);
}

static void test_IsDhcpPacketForSpecificMac(const uint8_t* buf, size_t len)
{
    unsigned char* buf2;
	UCHAR mac_address[6];

	if ( len < sizeof(mac_address) ) {
		return;
	}
	memcpy(&mac_address, buf, sizeof(mac_address));
	buf += sizeof(mac_address);
	len -= sizeof(mac_address);

    buf2 = clone(buf, len);
	IsDhcpPacketForSpecificMac(buf2, len, mac_address);
    free(buf2);
}

static void test_AdjustTcpMssL2(const uint8_t* buf, size_t len)
{
    unsigned char* buf2;
    struct {
        UINT mss;
        USHORT tag_vlan_tpid;
    } params;

	if ( len < sizeof(params) ) {
		return;
	}
	memcpy(&params, buf, sizeof(params));
	buf += sizeof(params);
	len -= sizeof(params);

    buf2 = clone(buf, len);
	AdjustTcpMssL2(buf2, len, params.mss, params.tag_vlan_tpid);
    free(buf2);
}

static void test_VLanRemoveTag(const uint8_t* buf, size_t len)
{
    unsigned char* buf2;
    void* packet_data;
	UINT packet_size;
    struct {
    	UINT vlan_id, vlan_tpid;
    } params;

	if ( len < sizeof(params) ) {
		return;
	}
	memcpy(&params, buf, sizeof(params));
	buf += sizeof(params);
	len -= sizeof(params);

    buf2 = clone(buf, len);
    packet_data = buf2;
    packet_size = len;
	VLanRemoveTag(&packet_data, &packet_size, params.vlan_id, params.vlan_tpid);
    free(buf2);
}

static void test_BuildIPv6(const uint8_t* buf, size_t len)
{
    unsigned char* buf2;
    struct {
        IPV6_ADDR src_ip, dest_ip;
        UINT id;
        UCHAR protocol, hop_limit;
    } params;

	if ( len < sizeof(params) ) {
		return;
	}
	memcpy(&params, buf, sizeof(params));
	buf += sizeof(params);
	len -= sizeof(params);

    buf2 = clone(buf, len);
	FreeBuf(BuildIPv6(
                &params.dest_ip,
                &params.src_ip,
                params.id,
                params.protocol,
                params.hop_limit,
                buf2,
                len));
    free(buf2);
}

static void test_BuildICMPv6(const uint8_t* buf, size_t len)
{
    unsigned char* buf2;
    struct {
        IPV6_ADDR src_ip, dest_ip;
        UCHAR hop_limit, type, code;
        UINT id;
    } params;

	if ( len < sizeof(params) ) {
		return;
	}
	memcpy(&params, buf, sizeof(params));
	buf += sizeof(params);
	len -= sizeof(params);

    buf2 = clone(buf, len);
	FreeBuf(BuildICMPv6(
                &params.src_ip,
                &params.dest_ip,
                params.hop_limit,
                params.type,
                params.code,
                buf2,
                len,
                params.id));
    free(buf2);
}

static void test_BuildICMPv6NeighborSoliciation(const uint8_t* buf, size_t len)
{
    struct {
        UCHAR mac_address[6];
        IPV6_ADDR src_ip, target_ip;
        UINT id;
    } params;

	if ( len < sizeof(params) ) {
		return;
	}
	memcpy(&params, buf, sizeof(params));
	buf += sizeof(params);
	len -= sizeof(params);

	FreeBuf(BuildICMPv6NeighborSoliciation(
                &params.src_ip,
                &params.target_ip,
                params.mac_address,
                params.id));
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    len /= 2;
   
    FuzzingSetRecvRandom(1);
    FuzzingSetSendRandom(1);
    FuzzingSetRecvInput((unsigned char*)buf + len, len);

    test_IcmpParseResult(buf, len);
    test_BuildIPv6(buf, len);
    test_IcmpEchoSend(buf, len);
    test_IsDhcpPacketForSpecificMac(buf, len);
    test_AdjustTcpMssL2(buf, len);
    test_VLanRemoveTag(buf, len);
    test_BuildICMPv6(buf, len);
    test_BuildICMPv6NeighborSoliciation(buf, len);

    return 0;
}
