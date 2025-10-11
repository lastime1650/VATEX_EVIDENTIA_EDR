#ifndef DLP_KERNEL_HPP
#define DLP_KERNEL_HPP

#include "util.hpp"
/*

	1) 전역 정책은 < 해시 맵>			      <<DLP_INFO>>
	2) 정책 별 { 화이트리스트 } 는 LIST_ENTRY <<WhiteList>>


	```psuedo
	{

		BOOLEAN is_enable?
		FILE_INFO {
			Size : ULONG64,
			File_Reference_Number : ULONG64
		}

		Policy {
			Global : {},
			WhiteList : LIST_ENTRY Header
		}

	}
	```

	?WhiteList
	GLobal의 한계를 뛰어넘으며, GLobal 정책보다 우선순위를 가짐. 
	MiniFilter에서 해당 파일에 대해 접근할 때, 주체(프로세스 리퀘스터)에 따라 개별적인 정책( Global과 같은 포맷)을 적용하는 개념 (동적이므로, LIST_ENTRY 사용해야함 ) 


*/
namespace DLP
{
	
	namespace resource
	{
		struct _DLP_Policy
		{
			struct { BOOLEAN is_block; } WRITE;
			struct { BOOLEAN is_block; } READ;
			struct { BOOLEAN is_block; } RENAME;
			struct { BOOLEAN is_block; } OPEN;
			struct { BOOLEAN is_block; } ACCESS_with_EXTERNAL_DEVICES;
		};

		// 파일 당 정책 노드중 "실행프로세스의 화이트리스트"기반 특별 개별 정책
		typedef struct _DLP_WhiteList_Node_Policy
		{
			LIST_ENTRY Entry;  // 양방향 연결 리스트

			struct _DLP_Policy Policy;

			ULONG64 ProcessEXE_FileReferenceNumber;  // 프로세스 실행 파일의 FRN (EXE 파일 기준)
		} DLP_WhiteList_Node_Policy, * P_DLP_WhiteList_Node_Policy;

		// 파일당 정보 및 정책 노드
		typedef struct _DLP_Info
		{
			BOOLEAN is_enable = FALSE;

			struct {
				ULONG64 FileSize;
				ULONG64 FileReferenceNumber;
			} FILE;

			struct {
				struct {
					struct _DLP_Policy Policy;
				} Global;

				LIST_ENTRY WhiteListHeader; // 최대 512개 노드까지
			} Policy;

		} DLP_Info, * PDLP_Info;

		namespace hashMap
		{
			typedef struct _DLP_TABLE_ENTRY {
				ULONG64 FileReferenceNumber;
				PDLP_Info Info;
			} DLP_TABLE_ENTRY, * PDLP_TABLE_ENTRY;

			// Key: ProtectFile 의 FRN ( File Reference Number ( ULONG64 ) )
			// Value: DLP::resource::PDLP_Info 값
			extern RTL_GENERIC_TABLE g_DlpTable;
			extern EX_PUSH_LOCK g_DlpTableLock;


			BOOLEAN InsertOrUpdate(DLP::resource::PDLP_Info Info); // DLP_Info 삽입 -> 없으면 생성 후 삽입
			DLP::resource::PDLP_Info Lookup(ULONG64 ProtectedFRN); // 맵에 저장된 DLP_Info 찾기
			BOOLEAN Remove(ULONG64 ProtectedFRN);				   // 맵에 저장된 DLP_Info 삭제
		}
	}

	NTSTATUS DLP_INITIALIZE();

	/*
		MiniFilter Use
	*/
	BOOLEAN CheckDlp( _Out_ struct DLP::resource::_DLP_Policy* Policy, HANDLE Requester_ProcessId, ULONG64 ProtectFileReferenceNumber); // 정책이 있는 지 해시맵 탐색하고, 정책 가져온 다음, 화이트리스트 탐색후 Global 까지 최종적으로 본다음, 정책 반환


	BOOLEAN CleanUp_DLP();

	namespace Helper
	{
		// Step 1
		BOOLEAN Make_DLP_INFO(
			DLP::resource::PDLP_Info* Out_DLP_Info,

			ULONG64 ProtectFile_FRN,
			ULONG64 FileSize,

			struct DLP::resource::_DLP_Policy GLOBAL_policy

		);

		BOOLEAN Set_Enable_DLP_INFO(ULONG64 ProcessEXE_FRN);

		BOOLEAN Update_DLP_INFO_Global( // 이미 존재하는 경우, 업데이트. 없는 경우 추가. 
			ULONG64 ProcessEXE_FRN,
			struct DLP::resource::_DLP_Policy GLOBAL_policy
		);
		BOOLEAN Remove_DLP_INFO(
			ULONG64 ProcessEXE_FRN
		);

		// Step 2
		BOOLEAN Update_WhiteList( // 이미 존재하는 경우, 업데이트. 없는 경우 추가. 
			DLP::resource::PDLP_Info In_DLP_Info,

			ULONG64 ProcessEXE_FRN,

			struct DLP::resource::_DLP_Policy WHITE_policy
		);

		BOOLEAN Remove_WhiteList(
			ULONG64 ProcessEXE_FRN,
			DLP::resource::PDLP_Info In_DLP_Info
		);

		// 화이트 리스트 조회
		BOOLEAN Lookup_WhiteList(
			DLP::resource::PDLP_Info In_DLP_Info,
			ULONG64 ProcessEXE_FRN,

			DLP::resource::P_DLP_WhiteList_Node_Policy out_WhiteListNode
		);
	}

}

#endif