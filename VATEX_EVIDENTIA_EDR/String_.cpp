#include "String_.hpp"

namespace EDR
{
	namespace Util
	{
		namespace String
		{
			namespace Ansi2Unicode
			{
				BOOLEAN ANSI_to_UnicodeString(
					PCHAR InputChar,
					ULONG32 InputCharMaxSize,
					UNICODE_STRING* output_Unicode
				)
				{
					if (!InputChar || !output_Unicode || !InputCharMaxSize)
						return FALSE;

					ANSI_STRING ansi;
					RtlInitAnsiString(&ansi, InputChar);

					if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(output_Unicode, &ansi, TRUE)))
					{
						output_Unicode->Buffer = NULL;
						output_Unicode->Length = 0;
						output_Unicode->MaximumLength = 0;
						return FALSE;
					}

					return TRUE;
				}

				VOID Release_ANSI_to_UnicodeString(UNICODE_STRING* unicode)
				{
					if (unicode && unicode->Buffer)
					{
						RtlFreeUnicodeString(unicode);
					}
				}
			}
			namespace Unicode2Ansi
			{
				BOOLEAN UnicodeString_to_ANSI(PCUNICODE_STRING Input_Unicode, PCHAR* AnsiString, ULONG32* AnsiStringMaxLength)
				{
					if (!Input_Unicode || !AnsiString || !AnsiStringMaxLength)
						return FALSE;

					ANSI_STRING ansi;
					if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, (PCUNICODE_STRING)Input_Unicode, TRUE)))
					{
						return FALSE;
					}

					*AnsiString = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, ansi.MaximumLength, UnicodeString_to_CHAR_ALLOC_TAG);
					if (!*AnsiString)
						return FALSE;
					RtlCopyMemory(*AnsiString, ansi.Buffer, ansi.MaximumLength);

					*AnsiStringMaxLength = ansi.MaximumLength;


					RtlFreeAnsiString(&ansi);
					return TRUE;
				}
				VOID Release_UnicodeString_to_ANSI(PCHAR allocated_string)
				{
					if (allocated_string)
						ExFreePoolWithTag(allocated_string, UnicodeString_to_CHAR_ALLOC_TAG);
				}
			}
		}
	}
	
}