#ifndef HASH_H

#define HASH_H

#include <ntifs.h>
#include <ntstrsafe.h>
#include <bcrypt.h>

#define SHA256_BINARY_LENGTH      32 // SHA256 해시의 바이너리 길이 (바이트)
#define SHA256_STRING_LENGTH      64 // SHA256 해시의 16진수 문자열 길이 (NULL 제외)
#define SHA256_String_Byte_Length (SHA256_STRING_LENGTH + 1) // NULL 종단 문자 포함
#define HASH_ALLOC_TAG            'HahS' // 메모리 할당 태그

namespace EDR
{
	namespace Util
	{
		namespace Hash
		{
			namespace SHA256
			{
				ULONG SHA256_Hasing(PCHAR* Output_Hashed, _In_ PUCHAR Data, _In_ SIZE_T DataSize);
			}

			VOID Release_Hashed(PCHAR HashBytes);
		}
	}
}


#endif