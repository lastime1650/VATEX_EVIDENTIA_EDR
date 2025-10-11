#ifndef RESPONSE_BY_HASHMAP_HPP
#define RESPONSE_BY_HASHMAP_HPP

#include "util.hpp"
#include "EventLog.hpp"

// ���� ��ġ (�ؽø� ���, ���� ������ ����)

#define POOL_TAG 'hsTB'
namespace EDR
{
	namespace Response
	{
		/*
			[ Response ����/���� ��ġ ]
			A. ���Ͻý��� -> PASSIVE_LEVEL �̰�, PRE�ڵ鷯�̰�, IRP_MJ_CREATE�� ��,
			B. ���μ��� ���� -> ���� �޸𸮿� �÷��� �ִ� ���, �����ϰ�, �ش� �������� ����
			C. Remote IP ���� -> IP ��Ī
		*/
		namespace Enum
		{
			enum ResponseAction
			{
				Allow, // ���� ( �⺻������ ���� �� ) - ������Ʈ ����
				Denied, // ����
				Delete // ���� ( ���� �� �������� � ��ȿ )
			};

			// ���� ����� Ÿ���� ����
			typedef enum _BLOCK_ITEM_TYPE {
				BlockTypeFileSha256,    // ���� �ؽ� (UCHAR[65])  ( ���Ͻý��� �� ���μ��� ) 
				BlockTypeIpAddress      // IP �ּ� (��Ʈ��ũ)
            } BLOCK_ITEM_TYPE;
		}
		namespace Struct
		{
			// Generic Table�� ����� ���� ������ ����
			#pragma pack(push, 1)
			typedef struct _BLOCK_ENTRY {
				Enum::BLOCK_ITEM_TYPE Type;
				Enum::ResponseAction Action;
				// Ű(Key)�� �Ǵ� ������. ����ü�� �޸� ȿ��ȭ
				union {
					struct
					{
						UCHAR FileHash[65];
						ULONG64 FileSize;
					}File;
					CHAR IpAddress[46]; // IPv6 �ּұ��� ����� ���� ������ ũ��
				} Data;
			} BLOCK_ENTRY, * PBLOCK_ENTRY;
			#pragma pack(pop)

            
		}
        namespace HashTable {

            // ���� ������ (cpp ���Ͽ� ����)
            extern RTL_GENERIC_TABLE g_BlockTable;
            extern EX_PUSH_LOCK g_TableLock;

            // �ݹ� ��ƾ ����
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

            // �ʱ�ȭ �� ���� �Լ�
            NTSTATUS Initialize();
            BOOLEAN CleanUp();

            // ������ ���� �Լ� (�ܺ� �������̽�)
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

            // ��ȸ �Լ� (���� �ٽ�)
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