#pragma once
#include "KuCrypto/KuCryptoCommon.hpp"

#define AES_BLOCK_SIZE 16

#define Nb 4

typedef enum AesMode
{
	AES_ECB,
	AES_CBC,
	AES_CTR
} AES_MODE;

typedef enum AesKeySize
{
	AES_128,
	AES_192,
	AES_256
} AES_KEYSIZE;

struct AES_ctx
{
	uint8_t RoundKey[240];
	uint8_t Iv[16];
	uint8_t Nk;
	uint8_t Nr;
	AES_KEYSIZE KeySize;
};


namespace KuCrypto
{
	namespace Aes
	{
		VOID Aes128EcbEncryptSixteenBytes
		(
			_Inout_updates_all_(16) BYTE* Buffer,
			_In_reads_(16)          BYTE* Key
		);
	}
}