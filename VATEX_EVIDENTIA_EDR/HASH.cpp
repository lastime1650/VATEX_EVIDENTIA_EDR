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
                     PCHAR* Output_Hashed, // 성공 시 할당된 문자열 포인터를 반환
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


                    // Output_Hashed 포인터를 초기화하여 실패 시 NULL을 가리키도록 함
                    *Output_Hashed = NULL;

                    // 1. SHA256 알고리즘 공급자 열기
                    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
                    if (!NT_SUCCESS(status)) {
                        goto cleanup;
                    }

                    // 2. 해시 객체 생성
                    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
                    if (!NT_SUCCESS(status)) {
                        goto cleanup;
                    }

                    // 3. 데이터를 청크 단위로 나누어 해시 업데이트
                    

                    while (remainingSize > 0)
                    {
                        // 현재 청크의 크기를 ULONG의 최대값과 남은 데이터 크기 중 작은 값으로 결정
                        ULONG chunkSize = (remainingSize > MAXULONG) ? MAXULONG : (ULONG)remainingSize;

                        status = BCryptHashData(hHash, currentPosition, chunkSize, 0);
                        if (!NT_SUCCESS(status)) {
                            goto cleanup;
                        }

                        // 다음 데이터 위치로 포인터 이동 및 남은 크기 갱신
                        currentPosition += chunkSize;
                        remainingSize -= chunkSize;
                    }

                    // 4. 해시 계산 완료
                    status = BCryptFinishHash(hHash, hashData, SHA256_BINARY_LENGTH, 0);
                    if (!NT_SUCCESS(status)) {
                        goto cleanup;
                    }

                    // 5. 결과를 저장할 문자열 버퍼 할당
                    // PagedPool을 사용해도 안전한 IRQL PASSIVE_LEVEL에서 호출된다고 가정
                    hashString = (PCHAR)ExAllocatePool2(POOL_FLAG_PAGED, SHA256_String_Byte_Length, HASH_ALLOC_TAG);
                    if (hashString == NULL) {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                        goto cleanup;
                    }

                    // 6. 바이너리 해시를 16진수 문자열로 변환
                    for (ULONG i = 0; i < SHA256_BINARY_LENGTH; i++)
                    {
                        // NTSTRSAFE_PSTR 캐스팅은 필요하지 않으나 명시적으로 유지
                        RtlStringCchPrintfA(&hashString[i * 2], 3, "%02x", hashData[i]);
                    }
                    hashString[SHA256_STRING_LENGTH] = '\0'; // 명시적인 NULL 종단

                    // 성공적으로 완료되었으므로, 출력 포인터에 할당된 버퍼 주소를 넘겨줌
                    *Output_Hashed = hashString;
                    // status는 이미 STATUS_SUCCESS 상태

                cleanup:
                    if (hHash) {
                        BCryptDestroyHash(hHash);
                    }
                    if (hAlg) {
                        BCryptCloseAlgorithmProvider(hAlg, 0);
                    }

                    // 실패했고, 문자열 버퍼가 중간에 할당되었다면 해제
                    if (!NT_SUCCESS(status) && hashString != NULL) {
                        ExFreePoolWithTag(hashString, HASH_ALLOC_TAG);
                        *Output_Hashed = NULL; // 호출자가 해제 시도하지 않도록 NULL로 설정
                    }

                    if (NT_SUCCESS(status)) {
                        return SHA256_String_Byte_Length;
                    }
                    else {
                        return 0;
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