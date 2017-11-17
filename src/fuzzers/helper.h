void FuzzingSetRecvRandom(int i);
void FuzzingSetSendRandom(int i);
void FuzzingSetRecvInput(unsigned char* data, size_t size);
static void* clone(const uint8_t* buf, size_t len)
{
    unsigned char* ret = malloc(len);
    memcpy(ret, buf, len);
    return (void*)ret;
}

static char* to_string(const uint8_t* buf, size_t len)
{
    char* string = malloc(len+1);
    memcpy(string, buf, len);
    string[len] = 0;
    return string;
}

#ifdef FUZZING_MSAN
static void test_MSAN(unsigned char* data, size_t size)
{
    if ( data == NULL ) {
        return;
    }
    FILE* fp = fopen("/dev/null", "wb");
    fwrite(data, 1, size, fp);
    fclose(fp);
}
#endif
