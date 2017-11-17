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
    wchar_t username_w[1024];
    UCHAR mschap_v2_server_response_20[20];
    RADIUS_LOGIN_OPTION opt_dummy;
    unsigned char secret = 'S';

    memset(mschap_v2_server_response_20, 0, 20);
    Zero(&opt_dummy, sizeof(opt_dummy));
    opt_dummy.In_CheckVLanId = true;

    StrToUni(username_w, sizeof(username_w), "username");

    FuzzingSetRecvRandom(1);
    FuzzingSetSendRandom(1);
    FuzzingSetRecvInput((unsigned char*)buf, len);

    RadiusLogin(
            NULL,
            "x.x.x",
            1234,
            &secret,
            1,
            username_w,
            "password",
            0,
            mschap_v2_server_response_20,
            &opt_dummy,
            NULL);


    return 0;
}
