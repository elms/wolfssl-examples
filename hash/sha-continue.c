
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef NO_SHA
void usage(void)
{
    printf("./sha-continue <file to hash>\n");
    exit(-99);
}
#endif


#ifndef CHUNK_SIZE
#define CHUNK_SIZE 1
#endif

int main(int argc, char** argv)
{
    int ret = -1;
#ifndef NO_SHA
    wc_Sha sha;
    byte  hash[WC_SHA_DIGEST_SIZE];
    byte  rawInput[CHUNK_SIZE];
    FILE* inputStream;
    char* fName = NULL;
    int fileLength = 0;
    int i, chunkSz;
    int st = 0;
    int len = -1;
    char* state_name = NULL;
    
    if (argc < 2)
        usage();
    fName = argv[1];
    printf("Hash input file %s\n", fName);

    if (argc > 3) {
      st = atoi(argv[2]);
      len = atoi(argv[3]);
    }
    if (argc > 4) {
      state_name = argv[4];
    }

    inputStream = fopen(fName, "rb");
    if (inputStream == NULL) {
        printf("ERROR: Unable to open file\n");
        return -1;
    }

    /* find length of the file */
    fseek(inputStream, 0, SEEK_END);
    fileLength = (int) ftell(inputStream);
    if (len > 0 && len < fileLength)
      fileLength = len;

    printf("start and length %d %d %d\n", st, len, fileLength);
    fseek(inputStream, st, SEEK_SET);

    ret = wc_InitSha(&sha);
    if (ret != 0) {
        printf("Failed to initialize sha structure\n");
        fclose(inputStream);
    }

    if (st > 0 && state_name != NULL) {
      FILE* fst = fopen(state_name, "rb");
      if (fst != NULL) {
        int nr = fread(sha.digest, WC_SHA_DIGEST_SIZE, 1, fst);
        if (nr != 1) {
          printf("unable to recover state file %s, read %d\n", state_name, nr);
        }
        nr = fread(sha.buffer, sizeof(sha.buffer), 1, fst);
        if (nr != 1) {
          printf("unable to recover file %s, wrote %d\n", state_name, nr);
        }
        nr = fread(&sha.buffLen, sizeof(sha.buffLen), 1, fst);
        if (nr != 1) {
          printf("unable to recover buffLen file %s, wrote %d\n", state_name, nr);
        }
        nr = fread(&sha.loLen, sizeof(sha.loLen), 1, fst);
        if (nr != 1) {
          printf("unable to recover loLen file %s, wrote %d\n", state_name, nr);
        }
        nr = fread(&sha.hiLen, sizeof(sha.hiLen), 1, fst);
        if (nr != 1) {
          printf("unable to recover hiLen file %s, wrote %d\n", state_name, nr);
        }
        
        fclose(fst);
      } else {
        printf("unable to open recover state file %s\n", state_name);
      }
    }

    /* Loop reading a block at a time, finishing with any excess */
    for (i = 0; i < fileLength; i += CHUNK_SIZE) {
        chunkSz = CHUNK_SIZE;
        if (chunkSz > fileLength - i)
            chunkSz = fileLength - i;

        ret = fread(rawInput, 1, chunkSz, inputStream);
        if (ret != chunkSz) {
            printf("ERROR: Failed to read the appropriate amount\n");
            ret = -1;
            break;
        }

        ret = wc_ShaUpdate(&sha, rawInput, chunkSz);
        if (ret != 0) {
            printf("Failed to update the hash\n");
            break;
        }
    }

    if (state_name != NULL) {
      FILE* fst = fopen(state_name, "wb");
      if (fst != NULL) {
        int nw = fwrite(sha.digest, WC_SHA_DIGEST_SIZE, 1, fst);
        if (nw != 1) {
          printf("unable to save state file %s, wrote %d\n", state_name, nw);
        }
        nw = fwrite(sha.buffer, sizeof(sha.buffer), 1, fst);
        if (nw != 1) {
          printf("unable to save file %s, wrote %d\n", state_name, nw);
        }
        nw = fwrite(&sha.buffLen, sizeof(sha.buffLen), 1, fst);
        if (nw != 1) {
          printf("unable to save buffLen file %s, wrote %d\n", state_name, nw);
        }
        nw = fwrite(&sha.loLen, sizeof(sha.loLen), 1, fst);
        if (nw != 1) {
          printf("unable to save loLen file %s, wrote %d\n", state_name, nw);
        }
        nw = fwrite(&sha.hiLen, sizeof(sha.hiLen), 1, fst);
        if (nw != 1) {
          printf("unable to save hiLen file %s, wrote %d\n", state_name, nw);
        }
        
        fclose(fst);
      } else {
        printf("unable to open save state file %s\n", state_name);
      }
    }

    
    if (ret == 0) {
      ret = wc_ShaFinalRaw(&sha, hash);
    }
    if (ret != 0) {
        printf("ERROR: Hash operation failed");
    }
    else {
        printf("Hash Raw result is: ");
        for (i = 0; i < WC_SHA_DIGEST_SIZE; i++)
            printf("%02x", hash[i]);
        printf("\n");
    }

    if (ret == 0) {
        ret = wc_ShaFinal(&sha, hash);
    }
    if (ret != 0) {
        printf("ERROR: Hash operation failed");
    }
    else {
        printf("Hash result is: ");
        for (i = 0; i < WC_SHA_DIGEST_SIZE; i++)
            printf("%02x", hash[i]);
        printf("\n");
    }

    fclose(inputStream);
    wc_ShaFree(&sha);
#else
    printf("Please enable sha (--enable-sha) in wolfCrypt\n");
#endif
    return ret;
}
