#include "Sha3.hpp"

namespace KuCrypto
{
	namespace Sha
	{ 
		namespace Sha3
		{
			namespace Internal
			{
                static const uint64_t keccakf_rndc[24] = 
                {
                    SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
                    SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
                    SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
                    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
                    SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
                    SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
                    SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
                    SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
                    SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
                    SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
                    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
                    SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
                };

                static const unsigned keccakf_rotc[24] = 
                {
                    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
                    18, 39, 61, 20, 44
                };

                static const unsigned keccakf_piln[24] = 
                {
                    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
                    14, 22, 9, 6, 1
                };

                /* generally called after SHA3_KECCAK_SPONGE_WORDS-ctx->capacityWords words
                 * are XORed into the state s
                 */
                static void keccakf(uint64_t s[25])
                {
                    int i, j, round;
                    uint64_t t, bc[5];


                    for (round = 0; round < KECCAK_ROUNDS; round++) 
                    {

                        /* Theta */
                        for (i = 0; i < 5; i++)
                            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

                        for (i = 0; i < 5; i++) 
                        {
                            t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
                            for (j = 0; j < 25; j += 5)
                                s[j + i] ^= t;
                        }

                        /* Rho Pi */
                        t = s[1];
                        for (i = 0; i < 24; i++) 
                        {
                            j = keccakf_piln[i];
                            bc[0] = s[j];
                            s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
                            t = bc[0];
                        }

                        /* Chi */
                        for (j = 0; j < 25; j += 5) 
                        {
                            for (i = 0; i < 5; i++)
                                bc[i] = s[j + i];
                            for (i = 0; i < 5; i++)
                                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                        }

                        /* Iota */
                        s[0] ^= keccakf_rndc[round];
                    }
                }


                sha3_return_t sha3_init(sha3_context* ctx, unsigned bitSize)
                {
                    if (bitSize != 256 && bitSize != 384 && bitSize != 512)
                        return SHA3_RETURN_BAD_PARAMS;

                    KuCrypto::RtlSecureZeroMemory(ctx, sizeof(*ctx)); // memset(ctx, 0, sizeof(*ctx));
                    ctx->capacityWords = 2 * bitSize / (8 * sizeof(uint64_t));
                    return SHA3_RETURN_OK;
                }


                bool sha3_setKeccakFlag(sha3_context* ctx, bool UseKeccak)
                {
                    //flags &= SHA3_FLAGS_KECCAK;
                    ctx->capacityWords |= (UseKeccak == true ? SHA3_USE_KECCAK_FLAG : 0);
                    return UseKeccak;
                }


                void sha3_update(sha3_context* ctx, uint8_t* bufIn, uint64_t len)
                {

                    /* 0...7 -- how much is needed to have a word */
                    unsigned old_tail = (8 - ctx->byteIndex) & 7;

                    uint64_t words;
                    uint64_t tail;
                    uint64_t i;

                    const uint8_t* buf = bufIn;

                    SHA3_TRACE_BUF("called to update with:", buf, len);

                    SHA3_ASSERT(ctx->byteIndex < 8);
                    SHA3_ASSERT(ctx->wordIndex < sizeof(ctx->u.s) / sizeof(ctx->u.s[0]));

                    if (len < old_tail)
                    {
                        /* have no complete word or haven't started the word yet */
                        SHA3_TRACE("because %d<%d, store it and return", (unsigned)len,
                            (unsigned)old_tail);
                        /* endian-independent code follows: */
                        while (len--)
                            ctx->saved |= (uint64_t)(*(buf++)) << ((ctx->byteIndex++) * 8);
                        SHA3_ASSERT(ctx->byteIndex < 8);
                        return;
                    }

                    if (old_tail)
                    {              /* will have one word to process */
                        SHA3_TRACE("completing one word with %d bytes", (unsigned)old_tail);
                        /* endian-independent code follows: */
                        len -= old_tail;
                        while (old_tail--)
                            ctx->saved |= (uint64_t)(*(buf++)) << ((ctx->byteIndex++) * 8);

                        /* now ready to add saved to the sponge */
                        ctx->u.s[ctx->wordIndex] ^= ctx->saved;
                        SHA3_ASSERT(ctx->byteIndex == 8);
                        ctx->byteIndex = 0;
                        ctx->saved = 0;
                        if (++ctx->wordIndex ==
                            (SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords))) {
                            Internal::keccakf(ctx->u.s);
                            ctx->wordIndex = 0;
                        }
                    }

                    /* now work in full words directly from input */

                    SHA3_ASSERT(ctx->byteIndex == 0);

                    words = len / sizeof(uint64_t);
                    tail = len - words * sizeof(uint64_t);

                    SHA3_TRACE("have %d full words to process", (unsigned)words);

                    for (i = 0; i < words; i++, buf += sizeof(uint64_t))
                    {
                        const uint64_t t = (uint64_t)(buf[0]) |
                            ((uint64_t)(buf[1]) << 8 * 1) |
                            ((uint64_t)(buf[2]) << 8 * 2) |
                            ((uint64_t)(buf[3]) << 8 * 3) |
                            ((uint64_t)(buf[4]) << 8 * 4) |
                            ((uint64_t)(buf[5]) << 8 * 5) |
                            ((uint64_t)(buf[6]) << 8 * 6) |
                            ((uint64_t)(buf[7]) << 8 * 7);

                        // #if defined(__x86_64__ ) || defined(__i386__)
                        //     SHA3_ASSERT(memcmp(&t, buf, 8) == 0);
                        // #endif

                        ctx->u.s[ctx->wordIndex] ^= t;
                        if (++ctx->wordIndex ==
                            (SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords)))
                        {
                            Internal::keccakf(ctx->u.s);
                            ctx->wordIndex = 0;
                        }
                    }

                    SHA3_TRACE("have %d bytes left to process, save them", (unsigned)tail);

                    /* finally, save the partial word */
                    SHA3_ASSERT(ctx->byteIndex == 0 && tail < 8);
                    while (tail--)
                    {
                        SHA3_TRACE("Store byte %02x '%c'", *buf, *buf);
                        ctx->saved |= (uint64_t)(*(buf++)) << ((ctx->byteIndex++) * 8);
                    }
                    SHA3_ASSERT(ctx->byteIndex < 8);
                    SHA3_TRACE("Have saved=0x%016" PRIx64 " at the end", ctx->saved);
                }


                /* This is simply the 'update' with the padding block.
                 * The padding block is 0x01 || 0x00* || 0x80. First 0x01 and last 0x80
                 * bytes are always present, but they can be the same byte.
                 */
                void const* sha3_finalize(sha3_context* ctx)
                {
                    SHA3_TRACE("called with %d bytes in the buffer", ctx->byteIndex);

                    /* Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
                     * use 1<<2 below. The 0x02 below corresponds to the suffix 01.
                     * Overall, we feed 0, then 1, and finally 1 to start padding. Without
                     * M || 01, we would simply use 1 to start padding. */

                    uint64_t t;

                    if (ctx->capacityWords & SHA3_USE_KECCAK_FLAG)
                    {
                        /* Keccak version */
                        t = (uint64_t)(((uint64_t)1) << (ctx->byteIndex * 8));
                    }
                    else {
                        /* SHA3 version */
                        t = (uint64_t)(((uint64_t)(0x02 | (1 << 2))) << ((ctx->byteIndex) * 8));
                    }

                    ctx->u.s[ctx->wordIndex] ^= ctx->saved ^ t;

                    ctx->u.s[SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords) - 1] ^=
                        SHA3_CONST(0x8000000000000000UL);
                    Internal::keccakf(ctx->u.s);

                    /* Return first bytes of the ctx->s. This conversion is not needed for
                     * little-endian platforms e.g. wrap with #if !defined(__BYTE_ORDER__)
                     * || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__!=__ORDER_LITTLE_ENDIAN__
                     *    ... the conversion below ...
                     * #endif */
                    {
                        unsigned i;
                        for (i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
                            const unsigned t1 = (uint32_t)ctx->u.s[i];
                            const unsigned t2 = (uint32_t)((ctx->u.s[i] >> 16) >> 16);
                            ctx->u.sb[i * 8 + 0] = (uint8_t)(t1);
                            ctx->u.sb[i * 8 + 1] = (uint8_t)(t1 >> 8);
                            ctx->u.sb[i * 8 + 2] = (uint8_t)(t1 >> 16);
                            ctx->u.sb[i * 8 + 3] = (uint8_t)(t1 >> 24);
                            ctx->u.sb[i * 8 + 4] = (uint8_t)(t2);
                            ctx->u.sb[i * 8 + 5] = (uint8_t)(t2 >> 8);
                            ctx->u.sb[i * 8 + 6] = (uint8_t)(t2 >> 16);
                            ctx->u.sb[i * 8 + 7] = (uint8_t)(t2 >> 24);
                        }
                    }

                    SHA3_TRACE_BUF("Hash: (first 32 bytes)", ctx->u.sb, 256 / 8);

                    return (ctx->u.sb);
                }

			}

            namespace Engine
            {
                sha3_return_t sha3_hashBuffer
                (
                    unsigned bitSize, 
                    bool useKeccak, 
                    uint8_t* in, 
                    uint64_t inBytes, 
                    void* out, 
                    uint64_t outBytes
                ) 
                {
                    sha3_return_t err;
                    sha3_context c;

                    KuCrypto::RtlSecureZeroMemory(&c, sizeof(c));

                    err = Internal::sha3_init(&c, bitSize);

                    if (err != SHA3_RETURN_OK)
                        return err;

                    if (Internal::sha3_setKeccakFlag(&c, useKeccak) != useKeccak)
                    {
                        return SHA3_RETURN_BAD_PARAMS;
                    }

                    Internal::sha3_update(&c, in, inBytes);

                    const void* h = Internal::sha3_finalize(&c);

                    if (outBytes > bitSize / 8)
                        outBytes = bitSize / 8;
                    KuCrypto::memcpy(out, h, outBytes);

                    KuCrypto::RtlSecureZeroMemory(&c, sizeof(c));

                    return SHA3_RETURN_OK;
                }
            }

             VOID ShaDigest
            (
                _In_                      enum SHA_DIGEST_LENGTH DigestLength,
                _In_                      uint64_t               InputDataSize,
                _In_reads_(InputDataSize) BYTE*                  InputData,
                _Out_writes_bytes_((DigestLength == SHA3_256) ? SHA3_256_DIGEST_SIZE : SHA3_512_DIGEST_SIZE)
                                          BYTE*                  OutputDigest
            )
            {
                 unsigned digest_length = 256;
                 if (DigestLength == SHA3_512) digest_length = 512;

                 Engine::sha3_hashBuffer(digest_length, true, InputData, InputDataSize, OutputDigest, (digest_length / 8));
            }
		}
	}
}