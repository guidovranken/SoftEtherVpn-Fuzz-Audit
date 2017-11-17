#include "Cedar/CedarPch.h"
#include "fuzzers/helper.h"

void BN_free(void*);

int LLVMFuzzerInitialize(int argc, char** argv)
{
    OSInit();
    InitCryptLibrary();
    InitInternational();
    return 0;
}

static void test_EasyEncrypt(const uint8_t* buf, size_t len)
{
	BUF *b;
    b = NewBuf();
	WriteBuf(b, (void*)buf, len);
    FreeBuf(EasyEncrypt(b));
    FreeBuf(b);
}

static void test_EasyDecrypt(const uint8_t* buf, size_t len)
{
	BUF *b;
    b = NewBuf();
	WriteBuf(b, (void*)buf, len);
    FreeBuf(EasyDecrypt(b));
    FreeBuf(b);
}

static void test_BinToBigNum(const uint8_t* buf, size_t len)
{
    BN_free( BinToBigNum((void*)buf, len) );
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	test_EasyEncrypt(buf, len);
	test_EasyDecrypt(buf, len);
	test_BinToBigNum(buf, len);
    return 0;
}
