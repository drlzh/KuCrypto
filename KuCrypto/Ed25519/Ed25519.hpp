#pragma once
#include "KuCrypto/KuCryptoCommon.hpp"

#define ED25519_SEED_SIZE          32
#define ED25519_PUBLIC_KEY_SIZE    32
#define ED25519_PRIVATE_KEY_SIZE   64
#define ED25519_SIGNATURE_SIZE     64
#define ED25519_SHARED_SECRET_SIZE 32

typedef int32_t fe[10];

typedef struct {
    fe X;
    fe Y;
    fe Z;
} ge_p2;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p3;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p1p1;

typedef struct {
    fe yplusx;
    fe yminusx;
    fe xy2d;
} ge_precomp;

typedef struct {
    fe YplusX;
    fe YminusX;
    fe Z;
    fe T2d;
} ge_cached;

// unsigned char seed[32], public_key[32], private_key[64], signature[64];

namespace KuCrypto
{
	namespace Ed25519
	{
        VOID
            KeyExchange
            (
                _In_reads_(ED25519_PUBLIC_KEY_SIZE)      BYTE* PublicKey,
                _In_reads_(ED25519_PRIVATE_KEY_SIZE)     BYTE* PrivateKey,
                _Out_writes_(ED25519_SHARED_SECRET_SIZE) BYTE* SharedSecret
            );

        VOID
            GenerateKeypair
            (
                _In_reads_opt_(ED25519_SEED_SIZE)      BYTE* Seed,
                _Out_writes_(ED25519_PUBLIC_KEY_SIZE)  BYTE* PublicKey,
                _Out_writes_(ED25519_PRIVATE_KEY_SIZE) BYTE* PrivateKey
            );

        VOID
            SignMessage
            (
                _In_                                 uint64_t MessageSize,
                _In_reads_(MessageSize)              BYTE* Message,
                _In_reads_(ED25519_PUBLIC_KEY_SIZE)  BYTE* PublicKey,
                _In_reads_(ED25519_PRIVATE_KEY_SIZE) BYTE* PrivateKey,
                _Out_writes_(ED25519_SIGNATURE_SIZE) BYTE* Signature
            );

        bool
            VerifySignature
            (
                _In_reads_(ED25519_SIGNATURE_SIZE)  BYTE* Signature,
                _In_                                uint64_t MessageSize,
                _In_reads_(MessageSize)             BYTE* Message,
                _In_reads_(ED25519_PUBLIC_KEY_SIZE) BYTE* PublicKey
            );

	}
}