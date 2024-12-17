#pragma once
#include "KuCrypto/KuCryptoCommon.hpp"


#define SHA3_KECCAK_SPONGE_WORDS (((1600)/8/*bits to byte*/)/sizeof(uint64_t))

#define KECCAK_ROUNDS 24


typedef struct sha3_context_ {
    uint64_t saved;             /* the portion of the input message that we
                                 * didn't consume yet */
    union 
    {                          /* Keccak's state */
        uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
        uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
    } u;
    unsigned byteIndex;         /* 0..7--the next byte after the set one
                                 * (starts from 0; 0--none are buffered) */
    unsigned wordIndex;         /* 0..24--the next word to integrate input
                                 * (starts from 0) */
    unsigned capacityWords;     /* the double size of the hash output in
                                 * words (e.g. 16 for Keccak 512) */
} sha3_context;


/*
enum SHA3_FLAGS 
{
    SHA3_FLAGS_NONE = 0,
    SHA3_FLAGS_KECCAK = 1
};
*/

enum SHA_DIGEST_LENGTH
{
    SHA3_256 = 0,
    SHA3_512 = 1
};

#define SHA3_256_DIGEST_SIZE 32
#define SHA3_512_DIGEST_SIZE 64


enum SHA3_RETURN 
{
    SHA3_RETURN_OK = 0,
    SHA3_RETURN_BAD_PARAMS = 1
};

  
typedef enum SHA3_RETURN sha3_return_t;

#define SHA3_ASSERT( x )
#define SHA3_TRACE( format, ...)
#define SHA3_TRACE_BUF(format, buf, l)


/*
 * This flag is used to configure "pure" Keccak, as opposed to NIST SHA3.
 */
#define SHA3_USE_KECCAK_FLAG 0x80000000
#define SHA3_CW(x) ((x) & (~SHA3_USE_KECCAK_FLAG))


#define SHA3_CONST(x) x##L


#define SHA3_ROTL64(x, y) (((x) << (y)) | ((x) >> ((sizeof(uint64_t)*8) - (y))))

namespace KuCrypto
{
    namespace Sha
    {
        namespace Sha3
        {
            VOID ShaDigest
            (
                _In_                      enum SHA_DIGEST_LENGTH DigestLength,
                _In_                      uint64_t               InputDataSize,
                _In_reads_(InputDataSize) BYTE*                  InputData,
                _Out_writes_bytes_((DigestLength == SHA3_256) ? SHA3_256_DIGEST_SIZE : SHA3_512_DIGEST_SIZE) 
                                          BYTE*                  OutputDigest
            );
        }
    }
}