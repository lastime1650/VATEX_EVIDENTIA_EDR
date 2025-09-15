#include "HASH.hpp"

namespace EDR
{
	namespace Util
	{
		namespace Hash
		{
			namespace SHA256
			{
                ULONG SHA256_Hasing(
                     PCHAR* Output_Hashed, // ���� �� �Ҵ�� ���ڿ� �����͸� ��ȯ
                     PUCHAR Data,
                     SIZE_T DataSize
                )
                {
                    NTSTATUS status = STATUS_SUCCESS;
                    BCRYPT_ALG_HANDLE hAlg = NULL;
                    BCRYPT_HASH_HANDLE hHash = NULL;
                    UCHAR hashData[SHA256_BINARY_LENGTH] = { 0 };
                    PCHAR hashString = NULL;

                    SIZE_T remainingSize = DataSize;
                    PUCHAR currentPosition = Data;


                    // Output_Hashed �����͸� �ʱ�ȭ�Ͽ� ���� �� NULL�� ����Ű���� ��
                    *Output_Hashed = NULL;

                    // 1. SHA256 �˰��� ������ ����
                    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
                    if (!NT_SUCCESS(status)) {
                        goto cleanup;
                    }

                    // 2. �ؽ� ��ü ����
                    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
                    if (!NT_SUCCESS(status)) {
                        goto cleanup;
                    }

                    // 3. �����͸� ûũ ������ ������ �ؽ� ������Ʈ
                    

                    while (remainingSize > 0)
                    {
                        // ���� ûũ�� ũ�⸦ ULONG�� �ִ밪�� ���� ������ ũ�� �� ���� ������ ����
                        ULONG chunkSize = (remainingSize > MAXULONG) ? MAXULONG : (ULONG)remainingSize;

                        status = BCryptHashData(hHash, currentPosition, chunkSize, 0);
                        if (!NT_SUCCESS(status)) {
                            goto cleanup;
                        }

                        // ���� ������ ��ġ�� ������ �̵� �� ���� ũ�� ����
                        currentPosition += chunkSize;
                        remainingSize -= chunkSize;
                    }

                    // 4. �ؽ� ��� �Ϸ�
                    status = BCryptFinishHash(hHash, hashData, SHA256_BINARY_LENGTH, 0);
                    if (!NT_SUCCESS(status)) {
                        goto cleanup;
                    }

                    // 5. ����� ������ ���ڿ� ���� �Ҵ�
                    // PagedPool�� ����ص� ������ IRQL PASSIVE_LEVEL���� ȣ��ȴٰ� ����
                    hashString = (PCHAR)ExAllocatePool2(POOL_FLAG_PAGED, SHA256_String_Byte_Length, HASH_ALLOC_TAG);
                    if (hashString == NULL) {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                        goto cleanup;
                    }

                    // 6. ���̳ʸ� �ؽø� 16���� ���ڿ��� ��ȯ
                    for (ULONG i = 0; i < SHA256_BINARY_LENGTH; i++)
                    {
                        // NTSTRSAFE_PSTR ĳ������ �ʿ����� ������ ��������� ����
                        RtlStringCchPrintfA(&hashString[i * 2], 3, "%02x", hashData[i]);
                    }
                    hashString[SHA256_STRING_LENGTH] = '\0'; // ������� NULL ����

                    // ���������� �Ϸ�Ǿ����Ƿ�, ��� �����Ϳ� �Ҵ�� ���� �ּҸ� �Ѱ���
                    *Output_Hashed = hashString;
                    // status�� �̹� STATUS_SUCCESS ����

                cleanup:
                    if (hHash) {
                        BCryptDestroyHash(hHash);
                    }
                    if (hAlg) {
                        BCryptCloseAlgorithmProvider(hAlg, 0);
                    }

                    // �����߰�, ���ڿ� ���۰� �߰��� �Ҵ�Ǿ��ٸ� ����
                    if (!NT_SUCCESS(status) && hashString != NULL) {
                        ExFreePoolWithTag(hashString, HASH_ALLOC_TAG);
                        *Output_Hashed = NULL; // ȣ���ڰ� ���� �õ����� �ʵ��� NULL�� ����
                    }

                    if (NT_SUCCESS(status)) {
                        return SHA256_String_Byte_Length;
                    }
                    else {
                        return 0;
                    }
                }


                /*
                    �ܺο��� Update������� SHA256�ؽ��Ҽ� �ֵ��� ��
                */
                namespace with_UpdateMode
                {

                    // SHA256 �ʱ�ȭ
                    BOOLEAN SHA256_Initialize(struct SHA256_UPDATE_CTX* ctx)
                    {
                        if (!ctx)
                            return FALSE;

                        NTSTATUS status = BCryptOpenAlgorithmProvider(
                            &ctx->hAlg,
                            BCRYPT_SHA256_ALGORITHM,
                            NULL,
                            0
                        );
                        if (!NT_SUCCESS(status))
                            return FALSE;

                        status = BCryptCreateHash(
                            ctx->hAlg,
                            &ctx->hHash,
                            NULL, // ���� ���� �Ҵ����� �ʰ� �ڵ� ũ�� ���
                            0,
                            NULL,
                            0,
                            0
                        );
                        if (!NT_SUCCESS(status))
                        {
                            BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
                            ctx->hAlg = NULL;
                            return FALSE;
                        }

                        return TRUE;
                    }

                    // SHA256 ������ ������Ʈ
                    BOOLEAN SHA256_Update(struct SHA256_UPDATE_CTX* ctx, PUCHAR CurrentPosition, ULONG32 chunkSize)
                    {
                        if (!ctx || !ctx->hHash || !CurrentPosition || chunkSize == 0)
                            return FALSE;

                        NTSTATUS status = BCryptHashData(
                            ctx->hHash,
                            CurrentPosition,
                            chunkSize,
                            0
                        );

                        return NT_SUCCESS(status);
                    }

                    ULONG32 SHA256_Finish(struct SHA256_UPDATE_CTX* ctx, PCHAR Buffer, ULONG32 BufferSize)
                    {
                        if (!ctx || !ctx->hHash || !Buffer || BufferSize < SHA256_String_Byte_Length)
                            return 0;

                        UCHAR hashData[SHA256_BINARY_LENGTH] = { 0 };

                        NTSTATUS status = BCryptFinishHash(ctx->hHash, hashData, SHA256_BINARY_LENGTH, 0);

                        // �ؽ� ���ҽ� ����
                        BCryptDestroyHash(ctx->hHash);
                        ctx->hHash = NULL;

                        if (ctx->hAlg)
                        {
                            BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
                            ctx->hAlg = NULL;
                        }

                        if (!NT_SUCCESS(status))
                            return 0;

                        // ���̳ʸ� �ؽ� -> 16���� ���ڿ�
                        for (ULONG i = 0; i < SHA256_BINARY_LENGTH; i++)
                        {
                            RtlStringCchPrintfA(&Buffer[i * 2], 3, "%02x", hashData[i]);
                        }
                        Buffer[SHA256_STRING_LENGTH] = '\0'; // NULL ����

                        return SHA256_String_Byte_Length;
                    }
                }

			}

            VOID Release_Hashed(PCHAR HashBytes)
            {
                if (HashBytes)
                    ExFreePoolWithTag(HashBytes, HASH_ALLOC_TAG);
            }
		}
	}
}