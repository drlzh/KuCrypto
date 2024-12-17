#include "KuCryptoCommon.hpp"


namespace KuCrypto
{

	void* memset_(void* _Dst, int _Val, uint64_t _Size)
	{
		unsigned char* dst = (unsigned char*)_Dst;
		unsigned char  val = (unsigned char)_Val;

		for (uint64_t i = 0; i < _Size; ++i)
		{
			dst[i] = val;
		}

		return _Dst;
	}

	void* memcpy_(void* _Dst, const void* _Src, uint64_t _MaxCount)
	{
		char* dst = (char*)_Dst;
		const char* src = (const char*)_Src;

		for (uint64_t i = 0; i < _MaxCount; ++i)
		{
			dst[i] = src[i];
		}

		return _Dst;
	}

}