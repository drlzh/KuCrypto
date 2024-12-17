#include "ChaCha256.hpp"






namespace KuCrypto
{
    namespace ChaCha
    {
        namespace ChaCha256
        {
            namespace Internal
            {
                static VC_INLINE void xor_block_512(const unsigned char* in, const unsigned char* prev, unsigned char* out)
                {
                    int i;
                    for (i = 0; i < 64; i++) out[i] = in[i] ^ prev[i];
                }

                static VC_INLINE void chacha_core(uint32* x, int r)
                {
                    int i;
                    for (i = 0; i < r; i++)
                    {
                        x[0] += x[4];
                        x[12] = rotatel32(x[12] ^ x[0], 16);
                        x[8] += x[12];
                        x[4] = rotatel32(x[4] ^ x[8], 12);
                        x[0] += x[4];
                        x[12] = rotatel32(x[12] ^ x[0], 8);
                        x[8] += x[12];
                        x[4] = rotatel32(x[4] ^ x[8], 7);

                        x[1] += x[5];
                        x[13] = rotatel32(x[13] ^ x[1], 16);
                        x[9] += x[13];
                        x[5] = rotatel32(x[5] ^ x[9], 12);
                        x[1] += x[5];
                        x[13] = rotatel32(x[13] ^ x[1], 8);
                        x[9] += x[13];
                        x[5] = rotatel32(x[5] ^ x[9], 7);

                        x[2] += x[6];
                        x[14] = rotatel32(x[14] ^ x[2], 16);
                        x[10] += x[14];
                        x[6] = rotatel32(x[6] ^ x[10], 12);
                        x[2] += x[6];
                        x[14] = rotatel32(x[14] ^ x[2], 8);
                        x[10] += x[14];
                        x[6] = rotatel32(x[6] ^ x[10], 7);

                        x[3] += x[7];
                        x[15] = rotatel32(x[15] ^ x[3], 16);
                        x[11] += x[15];
                        x[7] = rotatel32(x[7] ^ x[11], 12);
                        x[3] += x[7];
                        x[15] = rotatel32(x[15] ^ x[3], 8);
                        x[11] += x[15];
                        x[7] = rotatel32(x[7] ^ x[11], 7);

                        x[0] += x[5];
                        x[15] = rotatel32(x[15] ^ x[0], 16);
                        x[10] += x[15];
                        x[5] = rotatel32(x[5] ^ x[10], 12);
                        x[0] += x[5];
                        x[15] = rotatel32(x[15] ^ x[0], 8);
                        x[10] += x[15];
                        x[5] = rotatel32(x[5] ^ x[10], 7);

                        x[1] += x[6];
                        x[12] = rotatel32(x[12] ^ x[1], 16);
                        x[11] += x[12];
                        x[6] = rotatel32(x[6] ^ x[11], 12);
                        x[1] += x[6];
                        x[12] = rotatel32(x[12] ^ x[1], 8);
                        x[11] += x[12];
                        x[6] = rotatel32(x[6] ^ x[11], 7);

                        x[2] += x[7];
                        x[13] = rotatel32(x[13] ^ x[2], 16);
                        x[8] += x[13];
                        x[7] = rotatel32(x[7] ^ x[8], 12);
                        x[2] += x[7];
                        x[13] = rotatel32(x[13] ^ x[2], 8);
                        x[8] += x[13];
                        x[7] = rotatel32(x[7] ^ x[8], 7);

                        x[3] += x[4];
                        x[14] = rotatel32(x[14] ^ x[3], 16);
                        x[9] += x[14];
                        x[4] = rotatel32(x[4] ^ x[9], 12);
                        x[3] += x[4];
                        x[14] = rotatel32(x[14] ^ x[3], 8);
                        x[9] += x[14];
                        x[4] = rotatel32(x[4] ^ x[9], 7);
                    }
                }

                static VC_INLINE void chacha_hash(const uint32* in, uint32* out, int r)
                {
                    uint32 x[16];
                    int i;
                    memcpy(x, in, 64);
                    chacha_core(x, r);
                    for (i = 0; i < 16; ++i)
                        out[i] = x[i] + in[i];
                }

                static VC_INLINE void incrementSalsaCounter(uint32* input, uint32* block, int r)
                {
                    chacha_hash(input, block, r);
                    if (!++input[12])
                        ++input[13];
                }

                static VC_INLINE void do_encrypt(const unsigned char* in, uint64_t len, unsigned char* out, int r, uint64_t* posPtr, uint32* input, uint32* block)
                {
                    uint64_t i = 0, pos = *posPtr;
                    
                    /// <summary>
                    /// Previous implementation does not support streamed encryption
                    /// </summary>
                    /*
                    if (pos)
                    {
                        while (pos < len && pos < 64)
                        {
                            out[i] = in[i] ^ ((unsigned char*)block)[pos++];
                            ++i;
                        }
                        len -= i;
                    }
                    if (len)
                        pos = 0;

                    for (; len; len -= VC_MIN(64, len))
                    {
                        incrementSalsaCounter(input, block, r);
                        if (len >= 64)
                        {
                            xor_block_512(in + i, (unsigned char*)block, out + i);
                            i += 64;
                        }
                        else
                        {
                            for (; pos < len; pos++, i++)
                                out[i] = in[i] ^ ((unsigned char*)block)[pos];
                        }
                    }
                    *posPtr = pos;
                    */

                    // If there's a residual position from the previous block, continue from there
                    if (pos)
                    {
                        while (i < len && pos < 64)
                        {
                            out[i] = in[i] ^ ((unsigned char*)block)[pos];
                            ++i;
                            ++pos;
                        }
                        if (i == len) 
                        {
                            *posPtr = pos;
                            return;
                        }
                        pos = 0;
                    }

                    // Process full blocks
                    while (i + 64 <= len) 
                    {
                        incrementSalsaCounter(input, block, r);
                        xor_block_512(in + i, (unsigned char*)block, out + i);
                        i += 64;
                    }

                    // Process remaining bytes
                    if (i < len) 
                    {
                        incrementSalsaCounter(input, block, r);
                        for (pos = 0; i < len; ++i, ++pos) 
                        {
                            out[i] = in[i] ^ ((unsigned char*)block)[pos];
                        }
                    }

                    *posPtr = pos;
                }

                void ChaCha256Init(ChaCha256Ctx* ctx, const BYTE* key, const BYTE* iv, int rounds)
                {
                    ctx->internalRounds = rounds / 2;
                    ctx->pos = 0;

                    ctx->input_[12] = 0;
                    ctx->input_[13] = 0;
                    memcpy(ctx->input_ + 4, key, 32);
                    memcpy(ctx->input_ + 14, iv, 8);
                    ctx->input_[0] = 0x61707865;
                    ctx->input_[1] = 0x3320646E;
                    ctx->input_[2] = 0x79622D32;
                    ctx->input_[3] = 0x6B206574;
                }

                void ChaCha256Cryptor(ChaCha256Ctx* ctx, const BYTE* in, uint64_t len, BYTE* out)
                {
                    do_encrypt(in, len, out, ctx->internalRounds, &ctx->pos, ctx->input_, ctx->block_);
                }

            }

            VOID ChaChaEncrypt
            (
                _In_                        uint64_t PlaintextSize,
                _In_reads_(PlaintextSize)   BYTE*    Plaintext,
                _In_reads_(32)              BYTE*    Key,
                _In_reads_(8)               BYTE*    Iv,
                _Out_writes_(PlaintextSize) BYTE*    Ciphertext
            )
            {
                ChaCha256Ctx ctx;
                KuCrypto::RtlSecureZeroMemory(&ctx, sizeof(ctx));

                Internal::ChaCha256Init(&ctx, Key, Iv, 100);

                Internal::ChaCha256Cryptor(&ctx, Plaintext, PlaintextSize, Ciphertext);
                
                KuCrypto::RtlSecureZeroMemory(&ctx, sizeof(ctx));
            }

            VOID ChaChaDecrypt
            (
                _In_                         uint64_t CiphertextSize,
                _In_reads_(CiphertextSize)   BYTE*    Ciphertext,
                _In_reads_(32)               BYTE*    Key,
                _In_reads_(8)                BYTE*    Iv,
                _Out_writes_(CiphertextSize) BYTE*    Plaintext
            )
            {
                ChaCha256Ctx ctx;
                KuCrypto::RtlSecureZeroMemory(&ctx, sizeof(ctx));

                Internal::ChaCha256Init(&ctx, Key, Iv, 100);

                Internal::ChaCha256Cryptor(&ctx, Ciphertext, CiphertextSize, Plaintext);
                
                KuCrypto::RtlSecureZeroMemory(&ctx, sizeof(ctx));
            }
        }
    }
}