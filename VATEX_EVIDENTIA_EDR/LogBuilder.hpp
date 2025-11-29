#ifndef LOGBUILDER_HPP
#define LOGBUILDER_HPP

#include <ntddk.h>
#include "EventLog.hpp"

#define LOGBUILD_FLAG 'LOGB'
#define LOGBUILD_Possible_Size_byte 4 // 4byte 크기 지원
#define LOGBUILD_Buffer_Tail "_____END" 

namespace EDR
{
    namespace LogBuilder
    {


        // 로그 빌더 구조체 (스택에 선언해서 사용)
        typedef struct _LOG_BUILDER_CTX {
            EDR::EventLog::Enum::EventLog_Enum LogType;

            PUCHAR Buffer;
            SIZE_T Size;

            ULONG32 DataCount; // 추가된 횟수

            BOOLEAN Is_not_Init;       
        } LOG_BUILDER_CTX, * PLOG_BUILDER_CTX;

        FORCEINLINE
            PLOG_BUILDER_CTX Create_LOG_BUILDER_CTX()
        {
            POOL_FLAGS AllocFlag = (KeGetCurrentIrql() == PASSIVE_LEVEL) ? POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED;
            return (PLOG_BUILDER_CTX)ExAllocatePool2(AllocFlag, sizeof(LOG_BUILDER_CTX), LOGBUILD_FLAG);
        }

        FORCEINLINE
            void Terminate_LOG_BUILDER_CTX(PLOG_BUILDER_CTX ctx)
        {
            if(ctx)
                ExFreePoolWithTag(ctx, LOGBUILD_FLAG);
        }

        FORCEINLINE
            BOOLEAN LogBuilder_Init(
                _Inout_ PLOG_BUILDER_CTX CTX,
                _In_ EDR::EventLog::Enum::EventLog_Enum LogType
            )
        {
            SIZE_T To8Byte_LogType = (ULONG64)LogType;

            POOL_FLAGS AllocFlag = (KeGetCurrentIrql() == PASSIVE_LEVEL) ? POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED;

            USHORT InitialSize = sizeof(SIZE_T);
            CTX->Buffer = (PUCHAR)ExAllocatePool2(AllocFlag, InitialSize, LOGBUILD_FLAG);
            if (!CTX->Buffer)
                return FALSE;

            RtlCopyMemory(
                CTX->Buffer,
                &To8Byte_LogType,
                InitialSize
            );

            CTX->LogType = LogType;
            CTX->Size = InitialSize;
            CTX->Is_not_Init = FALSE;

            return TRUE;
        }

        FORCEINLINE
        BOOLEAN LogBuilder_Append(
            _Inout_ PLOG_BUILDER_CTX Builder,
            _In_ PUCHAR Data,
            _In_ SIZE_T DataSize
        )
        {
            if (Builder->Is_not_Init) return FALSE;

            POOL_FLAGS AllocFlag = (KeGetCurrentIrql() == PASSIVE_LEVEL) ? POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED;

            // 기존 + 새로운거 할당 시도
            SIZE_T allocated_size = Builder->Size + sizeof(DataSize) + DataSize;
            PUCHAR NewBuffer = (PUCHAR)ExAllocatePool2(AllocFlag, allocated_size, LOGBUILD_FLAG);
            if (!NewBuffer)
                return FALSE;

            // Copy
            RtlCopyMemory(                                      // 1. 이전 데이터 추가
                NewBuffer,
                Builder->Buffer,
                Builder->Size
            );

            RtlCopyMemory(                                      // 2. 실제 데이터 길이
                NewBuffer + Builder->Size,
                &DataSize,
                sizeof(DataSize)
            );

            RtlCopyMemory(
                NewBuffer + Builder->Size + sizeof(DataSize),   // 3. 실제 데이터 
                Data,
                DataSize
            );

            // 이전 데이터 할당 해제 후 바꾸기
            ExFreePoolWithTag(Builder->Buffer, LOGBUILD_FLAG);

            Builder->Buffer = NewBuffer;
            Builder->Size = allocated_size;
            Builder->DataCount += 1;

            return TRUE;
            
        }

        FORCEINLINE
            void LogBuilder_Closing(
                _Inout_ PLOG_BUILDER_CTX Builder
            )
        {
            PAGED_CODE();

            if (Builder->Is_not_Init || !Builder->Buffer)
                return;

            // "_END" 고정 문자열(4 bytes)
            ULONG32 TailSize = sizeof(LOGBUILD_Buffer_Tail)-1;           // 8

            SIZE_T allocated_size = Builder->Size + TailSize;
            PUCHAR NewBuffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, allocated_size, LOGBUILD_FLAG);
            if (!NewBuffer)
                return;

            // 기존 데이터 복사
            RtlCopyMemory(
                NewBuffer,
                Builder->Buffer,
                Builder->Size
            );

            // 2) 실제 "_____END"(8 bytes)
            RtlCopyMemory(
                NewBuffer + Builder->Size,
                LOGBUILD_Buffer_Tail,
                TailSize
            );

            // 기존 버퍼 교체
            ExFreePoolWithTag(Builder->Buffer, LOGBUILD_FLAG);

            Builder->Buffer = NewBuffer;
            Builder->Size = allocated_size;
        }

        FORCEINLINE
            void LogBuilder_Remove(
                _Inout_ PLOG_BUILDER_CTX Builder
            )
        {

            if (Builder->Is_not_Init || !Builder->Buffer)
                return;

            ExFreePoolWithTag(Builder->Buffer, LOGBUILD_FLAG);
            Builder->Size = 0;
            Builder->DataCount = 0;
            Builder->Is_not_Init = TRUE;
            Builder->LogType = (EDR::EventLog::Enum::EventLog_Enum)0;

        }

        namespace helper
        {
            FORCEINLINE
                PLOG_BUILDER_CTX CreateEventLog(
                    _In_ EDR::EventLog::Enum::EventLog_Enum LogType,
                    _In_ HANDLE ProcessId,
                    _In_ ULONG64 NanoTimestamp
                )
            {
                // 1) CTX 동적 생성
                PLOG_BUILDER_CTX ctx = Create_LOG_BUILDER_CTX();
                if (!ctx)
                    return nullptr;

                RtlZeroMemory(ctx, sizeof(LOG_BUILDER_CTX));

                // 2) 초기화 
                if (!LogBuilder_Init(ctx, LogType))
                {
                    Terminate_LOG_BUILDER_CTX(ctx);
                    return nullptr;
                }

                // 3) ProcessId 추가
                LogBuilder_Append(
                    ctx,
                    (PUCHAR)&ProcessId,
                    sizeof(ProcessId)
                );

                // 4) NanoTimestamp 추가
                LogBuilder_Append(
                    ctx,
                    (PUCHAR)&NanoTimestamp,
                    sizeof(NanoTimestamp)
                );

                // CTX 반환 (Closing은 필요시 호출 가능)
                return ctx;
            }

            FORCEINLINE
                BOOLEAN GetDataByIndex(
                    _In_ PLOG_BUILDER_CTX Ctx,
                    _In_ ULONG32 Index,
                    _Out_ PUCHAR* output_Buffer,
                    _Out_ SIZE_T* output_Buffer_Size
                )
            {

                if (!Ctx || Ctx->Is_not_Init || !Ctx->Buffer || !output_Buffer || !output_Buffer_Size)
                    return FALSE;

                if (Index >= Ctx->DataCount) // DataCount만큼만 유효
                    return FALSE;

                PUCHAR ptr = Ctx->Buffer + 8; // LogType 건너뛰기
                ULONG32 currentIndex = 0;

                while (currentIndex < Index)
                {
                    if (ptr + sizeof(SIZE_T) > Ctx->Buffer + Ctx->Size)
                        return FALSE; // 범위 초과 방지

                    SIZE_T dataSize = *(SIZE_T*)ptr;
                    ptr += sizeof(SIZE_T) + dataSize;

                    if (ptr > Ctx->Buffer + Ctx->Size)
                        return FALSE; // 범위 초과 방지

                    currentIndex++;
                }

                // ptr이 목표 데이터 위치
                if (ptr + sizeof(SIZE_T) > Ctx->Buffer + Ctx->Size)
                    return FALSE; // 범위 초과

                SIZE_T targetSize = *(SIZE_T*)ptr;
                PUCHAR targetData = ptr + sizeof(SIZE_T);

                // "_END" 영역을 벗어나지 않는지 체크
                if (targetData + targetSize > Ctx->Buffer + Ctx->Size)
                    return FALSE;

                *output_Buffer = targetData;
                *output_Buffer_Size = targetSize;

                return TRUE;
            }
        }
    }
}

#endif