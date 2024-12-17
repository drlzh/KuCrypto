#include "ChaChaRng.hpp"



namespace KuCrypto
{
	namespace ChaCha
	{
		namespace ChaChaRng
		{
			namespace Internal
			{

				static VC_INLINE void ChaCha20RngReKey(ChaCha20RngCtx* pCtx, int useCallBack)
				{
					/* fill rs_buf with the keystream */
					if (pCtx->m_rs_have)
						memset(pCtx->m_rs_buf + sizeof(pCtx->m_rs_buf) - pCtx->m_rs_have, 0, pCtx->m_rs_have);

					ChaCha::ChaCha256::Internal::ChaCha256Cryptor(&pCtx->m_chachaCtx, pCtx->m_rs_buf, sizeof(pCtx->m_rs_buf),
						pCtx->m_rs_buf);
					/* mix in optional user provided data */
					if (pCtx->m_getRandSeedCallback && useCallBack) {
						unsigned char dat[CHACHA20RNG_KEY_SIZE + CHACHA20RNG_IV_SIZE];
						uint64_t i;

						pCtx->m_getRandSeedCallback(dat, sizeof(dat));

						for (i = 0; i < (CHACHA20RNG_KEY_SIZE + CHACHA20RNG_IV_SIZE); i++)
							pCtx->m_rs_buf[i] ^= dat[i];

						burn(dat, sizeof(dat));
					}

					/* immediately reinit for backtracking resistance */
					ChaCha::ChaCha256::Internal::ChaCha256Init(&pCtx->m_chachaCtx, pCtx->m_rs_buf, pCtx->m_rs_buf + CHACHA20RNG_KEY_SIZE, 20);
					memset(pCtx->m_rs_buf, 0, CHACHA20RNG_KEY_SIZE + CHACHA20RNG_IV_SIZE);
					pCtx->m_rs_have = sizeof(pCtx->m_rs_buf) - CHACHA20RNG_KEY_SIZE - CHACHA20RNG_IV_SIZE;
				}

				static VC_INLINE void ChaCha20RngStir(ChaCha20RngCtx* pCtx)
				{
					ChaCha20RngReKey(pCtx, 1);

					/* invalidate rs_buf */
					pCtx->m_rs_have = 0;
					memset(pCtx->m_rs_buf, 0, CHACHA20RNG_RSBUF_SIZE);

					pCtx->m_rs_count = 1600000;
				}

				static VC_INLINE void ChaCha20RngStirIfNeeded(ChaCha20RngCtx* pCtx, uint64_t len)
				{
					if (pCtx->m_rs_count <= len) {
						ChaCha20RngStir(pCtx);
					}
					else
						pCtx->m_rs_count -= len;
				}

				void ChaCha20RngGetBytes(ChaCha20RngCtx* pCtx, BYTE* buffer, uint64_t bufferLen)
				{
					unsigned char* buf = (unsigned char*)buffer;
					unsigned char* keystream;
					uint64_t m;

					ChaCha20RngStirIfNeeded(pCtx, bufferLen);

					while (bufferLen > 0) {
						if (pCtx->m_rs_have > 0) {
							m = VC_MIN(bufferLen, pCtx->m_rs_have);
							keystream = pCtx->m_rs_buf + sizeof(pCtx->m_rs_buf) - pCtx->m_rs_have;
							if (buf)
							{
								memcpy(buf, keystream, m);
								buf += m;
							}
							memset(keystream, 0, m);
							bufferLen -= m;
							pCtx->m_rs_have -= m;
						}
						if (pCtx->m_rs_have == 0)
							ChaCha20RngReKey(pCtx, 0);
					}
				}

				void ChaCha20RngInit(ChaCha20RngCtx* pCtx, const BYTE* key, GetRandSeedFn rngSeedCallback, uint64_t InitialBytesToSkip)
				{
					ChaCha::ChaCha256::Internal::ChaCha256Init(&pCtx->m_chachaCtx, key, key + 32, 20);
					pCtx->m_getRandSeedCallback = rngSeedCallback;

					/* fill rs_buf with the keystream */
					pCtx->m_rs_have = 0;
					memset(pCtx->m_rs_buf, 0, sizeof(pCtx->m_rs_buf));
					pCtx->m_rs_count = 1600000;

					ChaCha20RngReKey(pCtx, 0);

					if (InitialBytesToSkip)
						ChaCha20RngGetBytes(pCtx, NULL, InitialBytesToSkip);
				}

			}

			namespace RandomSeed
			{
				VOID GetRandomSeed(BYTE* Seed, uint64_t Count)
				{
					auto lcg_psuedorandom_fallback = [&](BYTE* Seed, uint64_t Count) -> void
					{
						uint64_t pseudo_rand = 987654321ULL; // arbitrary seed
						for (uint64_t i = 0; i < Count; i++)
						{
							pseudo_rand = pseudo_rand * 6364136223846793005ULL + 1; // Linear congruential generator with parameters from MMIX by Donald Knuth
							*Seed++ = (uint8_t)((pseudo_rand >> 56) & 0xFF); // Take the top byte
						}
					};

					uint32_t rand_value;
					int result;
					uint64_t bytes_filled = 0;

					for (; bytes_filled < Count; bytes_filled++)
					{
						// Check if the RDRAND instruction is supported and succeeded
						result = _rdrand32_step(&rand_value);
						if (result)
						{
							// Calculate how many bytes to copy in this iteration
							uint64_t to_copy = sizeof(rand_value) < (Count - bytes_filled) ? sizeof(rand_value) : (Count - bytes_filled);

							// Copy the generated random data to the target buffer
							memcpy(Seed, &rand_value, to_copy);
							bytes_filled += to_copy;
						}
						else
						{
							// If RDRAND is not supported or fails, use the fallback
							lcg_psuedorandom_fallback(Seed, Count - bytes_filled);
							break;
						}
					}
				}
			}
			
			VOID ChaChaRngGetRandomBytes
			(
				_In_                           uint64_t OutputBufferSize,
				_Out_writes_(OutputBufferSize) BYTE*    OutputBuffer
			)
			{
				ChaCha20RngCtx ctx;
				KuCrypto::RtlSecureZeroMemory(&ctx, sizeof(ctx));

				BYTE seed [CHACHA20RNG_KEY_SIZE + CHACHA20RNG_IV_SIZE];

				RandomSeed::GetRandomSeed(seed, sizeof(seed));

				Internal::ChaCha20RngInit(&ctx, seed, RandomSeed::GetRandomSeed, 0);

				Internal::ChaCha20RngGetBytes(&ctx, OutputBuffer, OutputBufferSize);

				KuCrypto::RtlSecureZeroMemory(&ctx, sizeof(ctx));
			}

		}
	}
}