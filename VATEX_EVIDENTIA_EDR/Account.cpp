#include "Account.hpp"

namespace EDR
{
	namespace Util
	{
		namespace Account
		{
			namespace SID
			{
				NTSTATUS Get_PROCESS_SID(HANDLE ProcessId, _Inout_ PUNICODE_STRING out_SID)
				{
					if (!out_SID)
						return STATUS_INVALID_PARAMETER_2;

					if (KeGetCurrentIrql() != PASSIVE_LEVEL)
						return STATUS_INVALID_LEVEL;

					NTSTATUS status = STATUS_UNSUCCESSFUL;
					PEPROCESS Process = NULL;
					PACCESS_TOKEN accessToken = NULL;
					PTOKEN_USER tokenUser = NULL;


					status = PsLookupProcessByProcessId(ProcessId, &Process);
					if (!NT_SUCCESS(status))
						return status;

					// 1. ���μ����� �⺻ ��ū ���� ���
					accessToken = PsReferencePrimaryToken(Process);
					if (!accessToken)
						goto CleanUp;

					// 2. ��ū���� ����� ������ ��� ���� �ʿ��� ���� ũ�� ����
					status = SeQueryInformationToken(
						accessToken,
						TokenUser,
						(PVOID*)&tokenUser // PTOKEN_USER* �� PVOID* �� ĳ����
					);
					if (!NT_SUCCESS(status) || !tokenUser)
						goto CleanUp;

					status = RtlConvertSidToUnicodeString(out_SID, tokenUser->User.Sid, TRUE);
					if (!NT_SUCCESS(status))
						goto CleanUp;

				CleanUp:
					{
						if (tokenUser)
							ExFreePool(tokenUser);

						if (accessToken)
							PsDereferencePrimaryToken(accessToken);
						if (Process)
							ObDereferenceObject(Process);

						return status;
					}
				}
				VOID Release_PROCESS_SID(PUNICODE_STRING SID)
				{
					RtlFreeUnicodeString(SID);
				}

			}

		}
	}
}