#ifndef DLP_KERNEL_HPP
#define DLP_KERNEL_HPP

#include "util.hpp"
/*

	1) ���� ��å�� < �ؽ� ��>			      <<DLP_INFO>>
	2) ��å �� { ȭ��Ʈ����Ʈ } �� LIST_ENTRY <<WhiteList>>


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
	GLobal�� �Ѱ踦 �پ������, GLobal ��å���� �켱������ ����. 
	MiniFilter���� �ش� ���Ͽ� ���� ������ ��, ��ü(���μ��� ��������)�� ���� �������� ��å( Global�� ���� ����)�� �����ϴ� ���� (�����̹Ƿ�, LIST_ENTRY ����ؾ��� ) 


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

		// ���� �� ��å ����� "�������μ����� ȭ��Ʈ����Ʈ"��� Ư�� ���� ��å
		typedef struct _DLP_WhiteList_Node_Policy
		{
			LIST_ENTRY Entry;  // ����� ���� ����Ʈ

			struct _DLP_Policy Policy;

			ULONG64 ProcessEXE_FileReferenceNumber;  // ���μ��� ���� ������ FRN (EXE ���� ����)
		} DLP_WhiteList_Node_Policy, * P_DLP_WhiteList_Node_Policy;

		// ���ϴ� ���� �� ��å ���
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

				LIST_ENTRY WhiteListHeader; // �ִ� 512�� ������
			} Policy;

		} DLP_Info, * PDLP_Info;

		namespace hashMap
		{
			typedef struct _DLP_TABLE_ENTRY {
				ULONG64 FileReferenceNumber;
				PDLP_Info Info;
			} DLP_TABLE_ENTRY, * PDLP_TABLE_ENTRY;

			// Key: ProtectFile �� FRN ( File Reference Number ( ULONG64 ) )
			// Value: DLP::resource::PDLP_Info ��
			extern RTL_GENERIC_TABLE g_DlpTable;
			extern EX_PUSH_LOCK g_DlpTableLock;


			BOOLEAN InsertOrUpdate(DLP::resource::PDLP_Info Info); // DLP_Info ���� -> ������ ���� �� ����
			DLP::resource::PDLP_Info Lookup(ULONG64 ProtectedFRN); // �ʿ� ����� DLP_Info ã��
			BOOLEAN Remove(ULONG64 ProtectedFRN);				   // �ʿ� ����� DLP_Info ����
		}
	}

	NTSTATUS DLP_INITIALIZE();

	/*
		MiniFilter Use
	*/
	BOOLEAN CheckDlp( _Out_ struct DLP::resource::_DLP_Policy* Policy, HANDLE Requester_ProcessId, ULONG64 ProtectFileReferenceNumber); // ��å�� �ִ� �� �ؽø� Ž���ϰ�, ��å ������ ����, ȭ��Ʈ����Ʈ Ž���� Global ���� ���������� ������, ��å ��ȯ


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

		BOOLEAN Update_DLP_INFO_Global( // �̹� �����ϴ� ���, ������Ʈ. ���� ��� �߰�. 
			ULONG64 ProcessEXE_FRN,
			struct DLP::resource::_DLP_Policy GLOBAL_policy
		);
		BOOLEAN Remove_DLP_INFO(
			ULONG64 ProcessEXE_FRN
		);

		// Step 2
		BOOLEAN Update_WhiteList( // �̹� �����ϴ� ���, ������Ʈ. ���� ��� �߰�. 
			DLP::resource::PDLP_Info In_DLP_Info,

			ULONG64 ProcessEXE_FRN,

			struct DLP::resource::_DLP_Policy WHITE_policy
		);

		BOOLEAN Remove_WhiteList(
			ULONG64 ProcessEXE_FRN,
			DLP::resource::PDLP_Info In_DLP_Info
		);

		// ȭ��Ʈ ����Ʈ ��ȸ
		BOOLEAN Lookup_WhiteList(
			DLP::resource::PDLP_Info In_DLP_Info,
			ULONG64 ProcessEXE_FRN,

			DLP::resource::P_DLP_WhiteList_Node_Policy out_WhiteListNode
		);
	}

}

#endif