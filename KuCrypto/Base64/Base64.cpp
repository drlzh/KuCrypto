#include "KuCrypto/Base64/Base64.hpp"

namespace KuCrypto
{
	namespace Base64
	{
		namespace Internal
		{
			bool Base64Encode(const uint8_t *src, uint64_t src_len, char *dst, uint64_t &dst_len)
			{
				if (!src || !dst)  return false;

				const char alphabet[] =
				{
					'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
					'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
					'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
					'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
					'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
					'8', '9', '+', '/'
				};

				const char padchar = '=';
				uint64_t padlen = 0;

				char* out = dst;
				char* dst_end = dst + dst_len;
				uint64_t i = 0;
				while (i < src_len) {
					uint32_t chunk = 0;
					chunk |= static_cast<uint32_t>(src[i++]) << 16;
					if (i == src_len) {
						padlen = 2;
					}
					else {
						chunk |= static_cast<uint32_t>(src[i++]) << 8;
						if (i == src_len) {
							padlen = 1;
						}
						else {
							chunk |= static_cast<uint32_t>(src[i++]);
						}
					}

					uint64_t j = (chunk & 0x00fc0000) >> 18;
					uint64_t k = (chunk & 0x0003f000) >> 12;
					uint64_t l = (chunk & 0x00000fc0) >> 6;
					uint64_t m = (chunk & 0x0000003f);

					if (out + 4 > dst_end)
						return false;

					*out++ = alphabet[j];
					*out++ = alphabet[k];
					if (padlen > 1) *out++ = padchar;
					else *out++ = alphabet[l];
					if (padlen > 0) *out++ = padchar;
					else *out++ = alphabet[m];
				}

				dst_len = out - dst;
				return true;
			}


			uint64_t Base64EncodeGetRequiredLength(uint64_t src_len)
			{
				return src_len * 4 / 3 + 3;
			}


			uint64_t Base64DecodeGetRequiredLength(uint64_t src_len, const char* src) 
			{
				if (src == NULL) return 0;

				if (src_len % 4 != 0) 
				{
					return 0; // or handle the error as per application's error handling strategy
				}

				uint64_t padding = 0;

				// Check for padding characters at the end of the string
				if (src_len >= 1 && src[src_len - 1] == '=') 
				{
					padding++;
					if (src_len >= 2 && src[src_len - 2] == '=') 
					{
						padding++;
					}
				}

				// Every 4 bytes of Base64 text convert to 3 bytes of binary data
				uint64_t decoded_length = (src_len / 4) * 3;

				// Adjust for padding
				decoded_length -= padding;

				return decoded_length;
			}


			bool Base64Decode(const char* src, uint64_t src_len, uint8_t* dst, uint64_t& dst_len)
			{
				if (!src || !dst)
					return false;

				uint64_t buf = 0;
				uint64_t nbits = 0;
				uint64_t offset = 0;
				for (uint64_t i = 0; i < src_len; ++i) {
					char c = src[i];
					int d;

					if (c >= 'A' && c <= 'Z') {
						d = c - 'A';
					}
					else if (c >= 'a' && c <= 'z') {
						d = c - 'a' + 26;
					}
					else if (c >= '0' && c <= '9') {
						d = c - '0' + 52;
					}
					else if (c == '+') {
						d = 62;
					}
					else if (c == '/') {
						d = 63;
					}
					else {
						d = -1;
					}

					if (d != -1) {
						buf = (buf << 6) | d;
						nbits += 6;
						if (nbits >= 8) {
							nbits -= 8;
							if (offset == dst_len)
								return false;
							dst[offset++] = static_cast<uint8_t>(buf >> nbits);
							buf &= uint64_t((1 << nbits) - 1);
						}
					}
				}

				dst_len = offset;
				return true;
			}
		}

		bool 
		Base64Encode
		(
			_In_                                             uint64_t  MessageSize,
			_In_reads_(MessageSize)                          BYTE*     Message,
			_Inout_ _Deref_in_range_(0, *EncodedMessageSize) uint64_t& EncodedMessageSize,
			_Out_writes_opt_(*EncodedMessageSize)            CHAR*     EncodedMessage
		)   _Success_(return)
		{
			if (Message == NULL || MessageSize == 0) return false;
			
			if (EncodedMessageSize < Internal::Base64EncodeGetRequiredLength(MessageSize))
			{
				EncodedMessageSize = Internal::Base64EncodeGetRequiredLength(MessageSize);
				return false;
			}

			if (EncodedMessage == NULL) return false;

			RtlSecureZeroMemory(EncodedMessage, EncodedMessageSize);

			return Internal::Base64Encode(Message, MessageSize, EncodedMessage, EncodedMessageSize);
		}

		bool
		Base64Decode
		(
			_In_                                             uint64_t  EncodedMessageSize,
			_In_reads_(EncodedMessageSize)                   CHAR*     EncodedMessage,
			_Inout_ _Deref_in_range_(0, *DecodedMessageSize) uint64_t& DecodedMessageSize,
			_Out_writes_opt_(*DecodedMessageSize)            BYTE*     DecodedMessage
		)   _Success_(return)
		{
			if (EncodedMessage == NULL || EncodedMessageSize == 0) return false;

			if (DecodedMessageSize < Internal::Base64DecodeGetRequiredLength(EncodedMessageSize, EncodedMessage))
			{
				DecodedMessageSize = Internal::Base64DecodeGetRequiredLength(EncodedMessageSize, EncodedMessage);
				return false;
			}

			if (DecodedMessage == NULL) return false;

			RtlSecureZeroMemory(DecodedMessage, DecodedMessageSize);

			return Internal::Base64Decode(EncodedMessage, EncodedMessageSize, DecodedMessage, DecodedMessageSize);
		}
	}
}