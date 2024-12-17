#pragma once
#include "KuCrypto/KuCryptoCommon.hpp"

namespace KuCrypto
{
	namespace Base64
	{
		bool
		Base64Encode
		(
			_In_                                             uint64_t  MessageSize,
			_In_reads_(MessageSize)                          BYTE*     Message,
			_Inout_ _Deref_in_range_(0, *EncodedMessageSize) uint64_t& EncodedMessageSize,
			_Out_writes_opt_(*EncodedMessageSize)            CHAR*     EncodedMessage
		)   _Success_(return);

		bool
		Base64Decode
		(
			_In_                                             uint64_t  EncodedMessageSize,
			_In_reads_(EncodedMessageSize)                   CHAR*     EncodedMessage,
			_Inout_ _Deref_in_range_(0, *DecodedMessageSize) uint64_t& DecodedMessageSize,
			_Out_writes_opt_(*DecodedMessageSize)            BYTE*     DecodedMessage
		)   _Success_(return);
	}
}