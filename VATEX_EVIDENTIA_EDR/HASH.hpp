#ifndef HASH_H

#define HASH_H

#include <ntifs.h>
#include <ntstrsafe.h>
#include <bcrypt.h>

#define SHA256_BINARY_LENGTH      32 // SHA256 �ؽ��� ���̳ʸ� ���� (����Ʈ)
#define SHA256_STRING_LENGTH      64 // SHA256 �ؽ��� 16���� ���ڿ� ���� (NULL ����)
#define SHA256_String_Byte_Length (SHA256_STRING_LENGTH + 1) // NULL ���� ���� ����
#define HASH_ALLOC_TAG            'HahS' // �޸� �Ҵ� �±�

namespace EDR
{
	namespace Util
	{
		namespace Hash
		{
			namespace SHA256
			{
				ULONG SHA256_Hasing(PCHAR* Output_Hashed, _In_ PUCHAR Data, _In_ SIZE_T DataSize);

				namespace with_UpdateMode
				{
					struct SHA256_UPDATE_CTX
					{
						BCRYPT_ALG_HANDLE hAlg = NULL;
						BCRYPT_HASH_HANDLE hHash = NULL;


					};

					BOOLEAN SHA256_Initialize(struct SHA256_UPDATE_CTX* ctx );
					BOOLEAN SHA256_Update(struct SHA256_UPDATE_CTX* ctx, PUCHAR CurrentPosition, ULONG32 chunkSize);
					ULONG32 SHA256_Finish(struct SHA256_UPDATE_CTX* ctx, PCHAR Buffer, ULONG32 BufferSize);
				}

			}

			VOID Release_Hashed(PCHAR HashBytes);
		}
	}
}


#endif