#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

int LLVMFuzzerInitialize(int argc, char** argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char** argv)
{
    struct stat st;
    FILE *f;
    unsigned char *buf;
    size_t s;

    if ( argc != 2 ) {
        return 0;
    }

    LLVMFuzzerInitialize(argc, &argv);

    stat(argv[1], &st);

    f = fopen(argv[1], "rb");
    if (f == NULL) {
        return 0;
    }

    buf = malloc(st.st_size);

    s = fread(buf, 1, st.st_size, f);
    if ( s != (size_t)st.st_size ) {
        abort();
    }

    LLVMFuzzerTestOneInput(buf, s);

    free(buf);
    fclose(f);
    return 0;
}
