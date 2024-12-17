#pragma once

#include "KuCrypto/KuCryptoCommon.hpp"

#define WHIRLPOOL_DIGEST_SIZE 64


#define IsPowerOf2(n)	(((n) > 0) && (((n) & ((n)-1)) == 0))

#define ModPowerOf2(a,b)	((a) & ((b)-1))

#define IsAlignedOn(p,alignment) ((alignment==1) || (IsPowerOf2(alignment) ? ModPowerOf2((uint64_t)p, alignment) == 0 : (size_t)p % alignment == 0))

#define GetAlignmentOf(T) __alignof(T) // change to return 1 if should allow unaligned data access

#define IsAligned16(p)	IsAlignedOn(p, GetAlignmentOf(uint64))


typedef struct WHIRLPOOL_CTX {
	uint64 countLo;
	uint64 countHi;
	CRYPTOPP_ALIGN_DATA(16) uint64 data[8];
	CRYPTOPP_ALIGN_DATA(16) uint64 state[8];
} WHIRLPOOL_CTX;


namespace KuCrypto
{
	namespace Whirlpool
	{
		VOID WhirlpoolDigest
		(
			_In_                                uint64_t InputDataSize,
			_In_reads_(InputDataSize)           BYTE* InputData,
			_Out_writes_(WHIRLPOOL_DIGEST_SIZE) BYTE* OutputDigest
		);
	}
}