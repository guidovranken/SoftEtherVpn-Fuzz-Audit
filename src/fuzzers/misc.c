#include "Cedar/CedarPch.h"
#include "fuzzers/helper.h"

int LLVMFuzzerInitialize(int argc, char** argv)
{
    OSInit();
    InitInternational();
    return 0;
}

static void test_ParseUrl(const uint8_t* buf, size_t len)
{
	URL_DATA data;
    char* url = to_string(buf, len);
    memset(&data, 0, sizeof(data));

    ParseUrl(&data, url, false, NULL);

#ifdef FUZZING_MSAN
    test_MSAN(&data, sizeof(data));
#endif

    free(url);
}

static void test_IPToUniStr(const uint8_t* buf, size_t len)
{
    wchar_t* str = NULL;
    struct {
        USHORT sz;
        IP ip;
    } params;

    if ( len < sizeof(params) ) {
        return;
    }
    memcpy(&params, buf, sizeof(params));
    buf += sizeof(params);
    len -= sizeof(params);

    if ( params.sz == 0 ) {
        params.sz = 1;
    }

    str = malloc(params.sz * sizeof(wchar_t));
    IPToUniStr(str, params.sz * sizeof(wchar_t), &params.ip);
    free(str);
}

static void test_IPToUniStr32(const uint8_t* buf, size_t len)
{
    wchar_t* str = NULL;
    struct {
        USHORT sz;
        UINT ip;
    } params;

    if ( len < sizeof(params) ) {
        return;
    }
    memcpy(&params, buf, sizeof(params));
    buf += sizeof(params);
    len -= sizeof(params);

    if ( params.sz == 0 ) {
        params.sz = 1;
    }

    str = malloc(params.sz * sizeof(wchar_t));
    IPToUniStr32(str, params.sz * sizeof(wchar_t), params.ip);
    free(str);
}

static void test_IPToStr(const uint8_t* buf, size_t len)
{
    char* str = NULL;
    struct {
        USHORT sz;
        IP ip;
    } params;

    if ( len < sizeof(params) ) {
        return;
    }
    memcpy(&params, buf, sizeof(params));
    buf += sizeof(params);
    len -= sizeof(params);

    if ( params.sz == 0 ) {
        params.sz = 1;
    }

    str = malloc(params.sz);
    IPToStr(str, params.sz, &params.ip);
#ifdef FUZZING_MSAN
    test_MSAN(str, strlen(str));
#endif
    free(str);
}

static void test_StrToBin(const uint8_t* buf, size_t len)
{
    char* s = to_string(buf, len);;

	FreeBuf(StrToBin(s));

    free(s);
}

static void test_BinToStr(const uint8_t* buf, size_t len)
{
    USHORT sz;
    char* dest;

    if ( len < sizeof(sz) ) {
        return;
    }
    memcpy(&sz, buf, sizeof(sz));
    buf += sizeof(sz);
    len -= sizeof(sz);

    if ( sz == 0 ) {
        sz = 1;
    }

    dest = malloc(sz);
    /* Do this to ensure the buffer is not null-terminated before the call to
     * BinToStr()
     */
    memset(dest, 'x', sz);
    BinToStr(dest, sz, (void*)buf, len);
    /* This condition is obviously never true, but it forces the compiler to
     * implement an actual strlen() call, so we can be sure that out[] is
     * null-terminated after the call to ToStr64()
     */
    if ( strlen(dest) == 10000000 ) abort();
#ifdef FUZZING_MSAN
    test_MSAN(dest, strlen(dest));
#endif
    free(dest);
}

static void test_BinToStrEx(const uint8_t* buf, size_t len)
{
    USHORT sz;
    char* dest;

    if ( len < sizeof(sz) ) {
        return;
    }
    memcpy(&sz, buf, sizeof(sz));
    buf += sizeof(sz);
    len -= sizeof(sz);

    if ( sz == 0 ) {
        sz = 1;
    }

    dest = malloc(sz);
    BinToStrEx(dest, sz, (void*)buf, len);
    if ( strlen(dest) == 10000000 ) abort();
#ifdef FUZZING_MSAN
    test_MSAN(dest, strlen(dest));
#endif
    free(dest);
}

static void test_CopyBinToStr(const uint8_t* buf, size_t len)
{
    unsigned char* buf2 = clone(buf, len);
    char* ret = CopyBinToStr((void*)buf2, len);
#ifdef FUZZING_MSAN
    if ( ret != NULL ) {
        test_MSAN(ret, strlen(ret));
    }
#endif
    Free(ret);
    free(buf2);
}

static void test_IsNum(const uint8_t* buf, size_t len)
{
    char* s = to_string(buf, len);
    bool ret;

    ret = IsNum(s);

#ifdef FUZZING_MSAN
    test_MSAN(&ret, sizeof(ret));
#endif

    free(s);
}

static void test_NormalizeCrlf(const uint8_t* buf, size_t len)
{
    char* s = to_string(buf, len);
    char* ret;

    ret = NormalizeCrlf(s);
#ifdef FUZZING_MSAN
    if ( ret != NULL ) {
        test_MSAN(ret, strlen(ret));
    }
#endif
    Free(ret);

    free(s);
}

static void test_ParseToken(const uint8_t* buf, size_t len)
{
    char* s = to_string(buf, len);

    FreeToken(ParseToken(s, ",;"));

    free(s);
}

static void test_StartWith(const uint8_t* buf, size_t len)
{
    USHORT mod;
    size_t len1, len2;
    char* s1, *s2;
    bool ret;

    if ( len < sizeof(mod) ) {
        return;
    }
    memcpy(&mod, buf, sizeof(mod));
    buf += sizeof(mod);
    len -= sizeof(mod);

    if ( mod == 0 ) {
        return;
    }

    /* Split the input buffer into two parts of arbitrary lengths */
    len1 = len % mod;
    len2 = len - len1;

    s1 = to_string(buf, len1);
    s2 = to_string(buf+len1, len2);

    ret = StartWith(s1, s2);
#ifdef FUZZING_MSAN
    test_MSAN(&ret, sizeof(ret));
#endif

    free(s1);
    free(s2);
}

static void test_EndWith(const uint8_t* buf, size_t len)
{
    USHORT mod;
    size_t len1, len2;
    char* s1, *s2;
    bool ret;

    if ( len < sizeof(mod) ) {
        return;
    }
    memcpy(&mod, buf, sizeof(mod));
    buf += sizeof(mod);
    len -= sizeof(mod);

    if ( mod == 0 ) {
        return;
    }

    /* Split the input buffer into two parts of arbitrary lengths */
    len1 = len % mod;
    len2 = len - len1;

    s1 = to_string(buf, len1);
    s2 = to_string(buf+len1, len2);

    ret = EndWith(s1, s2);
#ifdef FUZZING_MSAN
    test_MSAN(&ret, sizeof(ret));
#endif

    free(s1);
    free(s2);
}

static void test_ToInt64(const uint8_t* buf, size_t len)
{
    char* s = to_string(buf, len);
    UINT64 ret;

    ret = ToInt64(s);
#ifdef FUZZING_MSAN
    test_MSAN(&ret, sizeof(ret));
#endif

    free(s);
}

static void test_ToStr64(const uint8_t* buf, size_t len)
{
    UINT64 value;
    char out[128];

    /* Do this to ensure the buffer is not null-terminated before the call to
     * ToStr64()
     */
    memset(out, 'X', sizeof(out));

    if ( len < sizeof(value) ) {
        return;
    }
    memcpy(&value, buf, sizeof(value));
    buf += sizeof(value);
    len -= sizeof(value);

    ToStr64(out, value);
    
    /* This condition is obviously never true, but it forces the compiler to
     * implement an actual strlen() call, so we can be sure that out[] is
     * null-terminated after the call to ToStr64()
     */
    if ( strlen(out) == 10000000 ) abort();
#ifdef FUZZING_MSAN
    test_MSAN(&out, strlen(out));
#endif
}

static void test_IsEmptyString(const uint8_t* buf, size_t len)
{
    char* s = to_string(buf, len);
    bool ret;

    ret = IsEmptyStr(s);

#ifdef FUZZING_MSAN
    test_MSAN(&ret, sizeof(ret));
#endif

    free(s);
}

static void test_MacToStr(const uint8_t* buf, size_t len)
{
    char* s;
    USHORT sz;
    unsigned char* buf2;

    if ( len < sizeof(sz) ) {
        return;
    }
    memcpy(&sz, buf, sizeof(sz));
    buf += sizeof(sz);
    len -= sizeof(sz);

    if ( sz == 0 ) {
        sz = 1;
    }

    if ( len < 6 ) {
        return;
    }

    buf2 = clone(buf, len);

    s = malloc(sz);
    /* Do this to ensure the buffer is not null-terminated before the call to
     * MacToStr()
     */
    memset(s, 'X', sz);

    MacToStr(s, sz, buf2);

    /* This condition is obviously never true, but it forces the compiler to
     * implement an actual strlen() call, so we can be sure that 's' is
     * null-terminated after the call to MacToStr()
     */
    if ( strlen(s) == 10000000 ) abort();
#ifdef FUZZING_MSAN
    test_MSAN(&s, strlen(s));
#endif

    free(s);
    free(buf2);
}

static void test_StrToIP(const uint8_t* buf, size_t len)
{
    IP ip;
    char* str = to_string(buf, len);
    StrToIP(&ip, str);
#ifdef FUZZING_MSAN
    test_MSAN(&ip, sizeof(ip));
#endif
    free(str);
}

static void test_UniStrToIP(const uint8_t* buf, size_t len)
{
    if ( len > 0 ) {
        IP ip;
        char* str = to_string(buf, len);
        char* wstr = malloc(len*4);
        StrToUni(wstr, len*4, str);
        UniStrToIP(&ip, wstr);
#ifdef FUZZING_MSAN
        test_MSAN(&ip, sizeof(ip));
#endif
        free(str);
        free(wstr);
    }
}

static void test_UniStrToIP32(const uint8_t* buf, size_t len)
{
    if ( len > 0 ) {
        char* str = to_string(buf, len);
        char* wstr = malloc(len*4);
        StrToUni(wstr, len*4, str);
        UniStrToIP32(wstr);
        free(str);
        free(wstr);
    }
}

static void test_IPToInAddr(const uint8_t* buf, size_t len)
{
    IP ip;
    if ( len >= sizeof(ip) ) {
        struct in_addr addr;
        memcpy(&ip, buf, sizeof(ip));
        IPToInAddr(&addr, &ip);
#ifdef FUZZING_MSAN
        test_MSAN(&addr, sizeof(addr));
#endif
    }
}

static void test_IPToInAddr6(const uint8_t* buf, size_t len)
{
    IP ip;
    if ( len >= sizeof(ip) ) {
        struct in6_addr addr;
        memcpy(&ip, buf, sizeof(ip));
        IPToInAddr6(&addr, &ip);
#ifdef FUZZING_MSAN
        test_MSAN(&addr, sizeof(addr));
#endif
    }
}

static void test_InAddrToIP(const uint8_t* buf, size_t len)
{
    struct in_addr addr;
    if ( len >= sizeof(addr) ) {
        IP ip;
        memcpy(&addr, buf, sizeof(addr));
        InAddrToIP(&ip, &addr);
#ifdef FUZZING_MSAN
    test_MSAN(&ip, sizeof(ip));
#endif
    }
}

static void test_InAddrToIP6(const uint8_t* buf, size_t len)
{
    struct in6_addr addr;
    if ( len >= sizeof(addr) ) {
        IP ip;
        memcpy(&addr, buf, sizeof(addr));
        InAddrToIP6(&ip, &addr);
#ifdef FUZZING_MSAN
    test_MSAN(&ip, sizeof(ip));
#endif
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    test_ParseUrl(buf, len);
    test_IPToUniStr(buf, len);
    test_IPToUniStr32(buf, len);
    test_IPToStr(buf, len);
    test_StrToBin(buf, len);
    test_BinToStr(buf, len);
    test_CopyBinToStr(buf, len); 
    test_IsNum(buf, len);
    test_NormalizeCrlf(buf, len);
    test_ParseToken(buf, len);
    test_StartWith(buf, len);
    test_EndWith(buf, len);
    test_ToInt64(buf, len);
    test_ToStr64(buf, len);
    test_IsEmptyString(buf, len);
    test_MacToStr(buf, len);
    test_StrToIP(buf, len);
    test_UniStrToIP32(buf, len);
    test_IPToInAddr(buf, len);
    test_IPToInAddr6(buf, len);
    test_InAddrToIP(buf, len);
    test_InAddrToIP6(buf, len);
    if ( 0 ) {
        /* This function call is disabled due to being very slow */
        test_BinToStrEx(buf, len);
    }
    return 0;
}
