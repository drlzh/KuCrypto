#pragma once

#ifdef _KERNEL_MODE
#include "KuDrvCommon.hpp"
#else
#include <Windows.h>
#include <intrin.h>
#endif

#include "CommonDataTypes.hpp"

#define VC_INLINE	__forceinline

#define rotr32(x,n)	(((x) >> n) | ((x) << (32 - n)))
#define rotl32(x,n)	(((x) << n) | ((x) >> (32 - n)))

#define rotl64(x,n)	(((x) << n) | ((x) >> (64 - n)))
#define rotr64(x,n)	(((x) >> n) | ((x) << (64 - n)))

#define rotater32(x,n)	rotr32(x, n)
#define rotatel32(x,n)	rotl32(x, n)

#define CRYPTOPP_ALIGN_DATA(x) __declspec(align(x))

#define VC_MIN(a,b)	((a)<(b))?(a):(b)

#define burn(mem,size)                             \
do                                                 \
{                                                  \
    volatile char *burnm = (volatile char *)(mem); \
    int burnc = size;                              \
    while (burnc--)                                \
        *burnm++ = 0;                              \
} while (0)


#define LL(x) x##ui64


namespace KuCrypto
{

	//void* memset(void* _Dst, int _Val, uint64_t _Size);
    FORCEINLINE
    void*
    memset
    (
        _Out_writes_bytes_all_(_Size) void*    _Dst,
        _In_                          int      _Val,
        _In_range_(>= , 1)            uint64_t _Size
    )
    {
        volatile char* vptr = (volatile char*)_Dst;

    #if defined(_M_AMD64)

        __stosb((PUCHAR)((ULONG64)vptr), (unsigned char)_Val, _Size);

    #else

        while (_Size)
        {

            #if !defined(_M_CEE) && (defined(_M_ARM) || defined(_M_ARM64))

            __iso_volatile_store8(vptr, (unsigned char)_Val);

            #else

            * vptr = (unsigned char)_Val;

            #endif

            vptr++;
            _Size--;
        }

    #endif // _M_AMD64

        return _Dst;
    }

    FORCEINLINE
    void*
    memcpy
    (
        _Out_writes_bytes_all_(_MaxCount) void* _Dst,
        _In_reads_bytes_(_MaxCount)       const void* _Src,
        _In_range_(>= , 1)                uint64_t _MaxCount
    )
    {
        volatile char* d = (volatile char*)_Dst;
        const volatile char* s = (const volatile char*)_Src;

    #if defined(_M_AMD64)

        __movsb((PUCHAR)((ULONG64)d), (PUCHAR)((ULONG64)s), _MaxCount);

    #else

        while (_MaxCount)
        {

        #if !defined(_M_CEE) && (defined(_M_ARM) || defined(_M_ARM64))

            __iso_volatile_store8(d, *s);

        #else

            * d = *s;

        #endif

            d++;
            s++;
            _MaxCount--;
        }

    #endif // _M_AMD64

        return _Dst;
    }

    FORCEINLINE
    PVOID
    RtlSecureZeroMemory
    (
        _Out_writes_bytes_all_(cnt) PVOID ptr,
        _In_                        uint64_t cnt
    )
    {
        volatile char* vptr = (volatile char*)ptr;

        #if defined(_M_AMD64)

        __stosb((PUCHAR)((ULONG64)vptr), 0, cnt);

        #else

        while (cnt) 
        {

            #if !defined(_M_CEE) && (defined(_M_ARM) || defined(_M_ARM64))

            __iso_volatile_store8(vptr, 0);

            #else

            * vptr = 0;

            #endif

            vptr++;
            cnt--;
        }

        #endif // _M_AMD64

        return ptr;
    }

}