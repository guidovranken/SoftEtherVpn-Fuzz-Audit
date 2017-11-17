#include "Cedar/CedarPch.h"
#include "fuzzers/helper.h"

int LLVMFuzzerInitialize(int argc, char** argv)
{
    OSInit();
    InitInternational();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	uint8_t choice;
	BUF* buf = NULL;

	while ( 1 ) {
		if ( len < sizeof(choice) ) {
			break;
		}
		choice = data[0];
		data += sizeof(choice);
		len -= sizeof(choice);

		switch ( choice ) {
			case	0:
				{
					USHORT sz;
					if ( len < sizeof(sz) ) {
						break;
					}
					memcpy(&sz, data, sizeof(sz));
					data += sizeof(sz);
					len -= sizeof(sz);

                    /* Curtail to remaining input size */
					if ( sz > len ) {
						sz = len;
					}

                    if ( buf ) {
                        FreeBuf(buf);
                    }
					buf = NewBufFromMemory((void*)data, sz);
				}
				break;
			case	1:
				{
                    if ( buf ) {
                        FreeBuf(buf);
                    }
					buf = NewBuf();
				}
				break;
			case	2:
				{
					if ( buf ) {
						USHORT sz;
						if ( len < sizeof(sz) ) {
							break;
						}
						memcpy(&sz, data, sizeof(sz));
						data += sizeof(sz);
						len -= sizeof(sz);

						FreeBuf( ReadBufFromBuf(buf, sz) );
					}
				}
			case	3:
				{
					if ( buf ) {
						USHORT sz;
						if ( len < sizeof(sz) ) {
							break;
						}
                        break;
						memcpy(&sz, data, sizeof(sz));
						data += sizeof(sz);
						len -= sizeof(sz);

                        /* Curtail to remaining input size */
                        if ( sz > len ) {
                            sz = len;
                        }

						ReadBuf(buf, (void*)data, sz);
					}
				}
				break;
			case	4:
				{
					if ( buf ) {
						USHORT sz;
						if ( len < sizeof(sz) ) {
							break;
						}
						memcpy(&sz, data, sizeof(sz));
						data += sizeof(sz);
						len -= sizeof(sz);
						AdjustBufSize(buf, sz);
					}
				}
				break;
			case	5:
				{
					if ( buf ) {
						SeekBufToBegin(buf);
					}
				}
				break;
			case	6:
				{
					if ( buf ) {
						SeekBufToEnd(buf);
					}
				}
				break;
			case	7:
				{
					if ( buf ) {
						USHORT sz;
						if ( len < sizeof(sz) ) {
							break;
						}
						memcpy(&sz, data, sizeof(sz));
						data += sizeof(sz);
						len -= sizeof(sz);
						SeekBuf(buf, sz, 0);
					}
				}
				break;
			case	8:
				{
					if ( buf ) {
						FreeBuf(buf);
						buf = NULL;
					}
				}
				break;
			case	9:
				{
					if ( buf ) {
						FreeBuf(ReadRemainBuf(buf));
					}
				}
				break;
			case	10:
				{
					if ( buf ) {
						ReadBufRemainSize(buf);
					}
				}
				break;
			case	11:
				{
					if ( buf ) {
						FreeBuf(CloneBuf(buf));
					}
				}
                break;
			case	12:
				{
					USHORT sz;
                    unsigned char* data2 = NULL;

					if ( len < sizeof(sz) ) {
						break;
					}
					memcpy(&sz, data, sizeof(sz));
					data += sizeof(sz);
					len -= sizeof(sz);

                    if ( buf ) {
                        FreeBuf(buf);
                    }

                    data2 = calloc(1, sz);
					buf = MemToBuf((void*)data2, sz);
                    free(data2);
				}
				break;
		}
	}

	if ( buf ) {
#ifdef FUZZING_MSAN
        test_MSAN(buf->Buf, buf->Size);
#endif
		FreeBuf(buf);
	}

    return 0;
}
