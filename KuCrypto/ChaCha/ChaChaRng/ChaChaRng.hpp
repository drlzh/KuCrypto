#pragma once

#include "KuCrypto/KuCryptoCommon.hpp"
#include "KuCrypto/ChaCha/ChaCha256/ChaCha256.hpp"


#define CHACHA20RNG_KEY_SIZE   32
#define CHACHA20RNG_IV_SIZE	   8
#define CHACHA20RNG_BLOCK_SIZE 64
#define CHACHA20RNG_RSBUF_SIZE (16 * CHACHA20RNG_BLOCK_SIZE)

typedef void (*GetRandSeedFn)(unsigned char* pbRandSeed, uint64_t cbRandSeed);

typedef struct
{
	ChaCha256Ctx m_chachaCtx; /* ChaCha20 context */
	unsigned char m_rs_buf[CHACHA20RNG_RSBUF_SIZE];	/* keystream blocks */
	uint64_t m_rs_have;	/* valid bytes at end of rs_buf */
	uint64_t m_rs_count; /* bytes till reseed */
	GetRandSeedFn m_getRandSeedCallback;
} ChaCha20RngCtx;


namespace KuCrypto
{
	namespace ChaCha
	{
		namespace ChaChaRng
		{
			VOID ChaChaRngGetRandomBytes
			(
				_In_                           uint64_t OutputBufferSize,
				_Out_writes_(OutputBufferSize) BYTE*    OutputBuffer
			);
		}
	}
}