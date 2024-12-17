#pragma once
#include "KuCrypto/KuCryptoCommon.hpp"

#pragma warning (disable:4706)

#define SHA2_512_DIGEST_SIZE 64

typedef struct sha512_context_ 
{
    uint64_t  length, state[8];
    uint64_t curlen;
    unsigned char buf[128];
} sha512_context;


#define ROR64c(x, y) \
    ( ((((x)&UINT64_C(0xFFFFFFFFFFFFFFFF))>>((uint64_t)(y)&UINT64_C(63))) | \
      ((x)<<((uint64_t)(64-((y)&UINT64_C(63)))))) & UINT64_C(0xFFFFFFFFFFFFFFFF))


#define STORE64H(x, y)                                                                     \
   { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); }


#define LOAD64H(x, y)                                                      \
   { x = (((uint64_t)((y)[0] & 255))<<56)|(((uint64_t)((y)[1] & 255))<<48) | \
         (((uint64_t)((y)[2] & 255))<<40)|(((uint64_t)((y)[3] & 255))<<32) | \
         (((uint64_t)((y)[4] & 255))<<24)|(((uint64_t)((y)[5] & 255))<<16) | \
         (((uint64_t)((y)[6] & 255))<<8)|(((uint64_t)((y)[7] & 255))); }


#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y)) 
#define S(x, n)         ROR64c(x, n)
#define R(x, n)         (((x) &UINT64_C(0xFFFFFFFFFFFFFFFF))>>((uint64_t)n))
#define Sigma0(x)       (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1(x)       (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0(x)       (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1(x)       (S(x, 19) ^ S(x, 61) ^ R(x, 6))


#ifndef MIN
#define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

#define UINT64_C(v) v ##ULL


namespace KuCrypto
{
    namespace Sha
    {
        namespace Sha2_512
        {
            namespace Internal
            {
                int sha512_init(sha512_context* md);
                int sha512_update(sha512_context* md, const unsigned char* in, uint64_t inlen);
                int sha512_final(sha512_context* md, unsigned char* out);
            }

            namespace Engine
            {
                int sha512(const unsigned char* message, uint64_t message_len, unsigned char* out);
            }


            VOID ShaDigest
            (
                _In_                               uint64_t InputDataLength,
                _In_reads_(InputDataLength)        BYTE*    InputData,
                _Out_writes_(SHA2_512_DIGEST_SIZE) BYTE*    OutputDigest
            );
        }
    }
}