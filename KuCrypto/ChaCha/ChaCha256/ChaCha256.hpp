#pragma once

#include "KuCrypto/KuCryptoCommon.hpp"

#define CHACHA256_KEY_SIZE 32
#define CHACHA256_IV_SIZE 16 // Should be 8, but 16 makes it a multiple of AES block size

typedef struct
{
    CRYPTOPP_ALIGN_DATA(16) uint32 block_[16];
    CRYPTOPP_ALIGN_DATA(16) uint32 input_[16];
    uint64_t pos;
    int internalRounds;
} ChaCha256Ctx;


namespace KuCrypto
{
    namespace ChaCha
    {
        namespace ChaCha256
        {
            namespace Internal
            {
                void ChaCha256Init(ChaCha256Ctx* ctx, const BYTE* key, const BYTE* iv, int rounds);
                void ChaCha256Cryptor(ChaCha256Ctx* ctx, const BYTE* in, uint64_t len, BYTE* out);
            }

            VOID ChaChaEncrypt
            (
                _In_                        uint64_t PlaintextSize,
                _In_reads_(PlaintextSize)   BYTE*    Plaintext,
                _In_reads_(32)              BYTE*    Key,
                _In_reads_(8)               BYTE*    Iv,
                _Out_writes_(PlaintextSize) BYTE*    Ciphertext
            );

            VOID ChaChaDecrypt
            (
                _In_                         uint64_t CiphertextSize,
                _In_reads_(CiphertextSize)   BYTE*    Ciphertext,
                _In_reads_(32)               BYTE*    Key,
                _In_reads_(8)                BYTE*    Iv,
                _Out_writes_(CiphertextSize) BYTE*    Plaintext
            );
        }
    }
}