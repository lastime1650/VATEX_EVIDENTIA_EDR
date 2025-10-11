#ifndef RESPONSE_BY_HASHMAP_HPP
#define RESPONSE_BY_HASHMAP_HPP

#include "util.hpp"
#include "EventLog.hpp"

// 차단 조치 (해시맵 기반, 현재 사용되지 않음)

#define POOL_TAG 'hsTB'
namespace EDR
{
	namespace Response
	{
		/*
			[ Response 대응/차단 조치 ]
			A. 파일시스템 -> PASSIVE_LEVEL 이고, PRE핸들러이고, IRP_MJ_CREATE일 떄,
			B. 프로세스 제거 -> 현재 메모리에 올려져 있는 경우, 제거하고, 해당 실행파일 제거
			C. Remote IP 차단 -> IP 매칭
		*/
		namespace Enum
		{
			enum ResponseAction
			{
				Allow, // 승인 ( 기본적으로 승인 함 ) - 블랙리스트 형태
				Denied, // 거절
				Delete // 삭제 ( 파일 및 실행파일 등에 유효 )
			};

			// 차단 대상의 타입을 정의
			typedef enum _BLOCK_ITEM_TYPE {
				BlockTypeFileSha256,    // 파일 해시 (UCHAR[65])  ( 파일시스템 및 프로세스 ) 
				BlockTypeIpAddress      // IP 주소 (네트워크)
            } BLOCK_ITEM_TYPE;
		}
		namespace Struct
		{
			// Generic Table에 저장될 실제 데이터 구조
			#pragma pack(push, 1)
			typedef struct _BLOCK_ENTRY {
				Enum::BLOCK_ITEM_TYPE Type;
				Enum::ResponseAction Action;
				// 키(Key)가 되는 데이터. 공용체로 메모리 효율화
				union {
					struct
					{
						UCHAR FileHash[65];
						ULONG64 FileSize;
					}File;
					CHAR IpAddress[46]; // IPv6 주소까지 충분히 저장 가능한 크기
				} Data;
			} BLOCK_ENTRY, * PBLOCK_ENTRY;
			#pragma pack(pop)

            
		}
        namespace HashTable {

            // 전역 데이터 (cpp 파일에 정의)
            extern RTL_GENERIC_TABLE g_BlockTable;
            extern EX_PUSH_LOCK g_TableLock;

            // 콜백 루틴 선언
            extern "C" RTL_GENERIC_COMPARE_RESULTS NTAPI CompareRoutine(
                _In_ RTL_GENERIC_TABLE* Table,
                _In_ PVOID FirstStruct,
                _In_ PVOID SecondStruct
            );

            extern "C" PVOID NTAPI AllocateRoutine(
                _In_ RTL_GENERIC_TABLE* Table,
                _In_ CLONG ByteSize
            );

            extern "C" VOID NTAPI FreeRoutine(
                _In_ RTL_GENERIC_TABLE* Table,
                _In_ PVOID Buffer
            );

            // 초기화 및 해제 함수
            NTSTATUS Initialize();
            BOOLEAN CleanUp();

            // 데이터 조작 함수 (외부 인터페이스)
            NTSTATUS AddFileBlock(
                _In_ const CHAR* FileHash,
                _In_ ULONG64 FileSize,
                _In_ Enum::ResponseAction Action
            );

            NTSTATUS AddIpBlock(
                _In_ const CHAR* IpAddress,
                _In_ Enum::ResponseAction Action
            );

            BOOLEAN RemoveFileBlock(
                _In_ const CHAR* FileHash,
                _In_ ULONG64 FileSize
            );

            BOOLEAN RemoveIpBlock(
                _In_ const CHAR* IpAddress
            );

            // 조회 함수 (가장 핵심)
            Enum::ResponseAction CheckFileAction(
                _In_ const CHAR* FileHash,
                _In_ ULONG64 FileSize
            );

            Enum::ResponseAction CheckIpAction(
                _In_ const CHAR* IpAddress
            );

        }
	}
}

#endif