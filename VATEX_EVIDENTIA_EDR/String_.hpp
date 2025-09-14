#ifndef STRING_H
#define STRING_H

#include <ntifs.h>

namespace EDR
{
	namespace Util
	{
		namespace String
		{
			namespace Ansi2Unicode
			{
				BOOLEAN ANSI_to_UnicodeString(PCHAR InputChar, ULONG32 InputCharMaxSize, UNICODE_STRING* output_Unicode);
				VOID Release_ANSI_to_UnicodeString(UNICODE_STRING* unicode);
			}
			namespace Unicode2Ansi
			{
				#define UnicodeString_to_CHAR_ALLOC_TAG 'USCT'
				BOOLEAN UnicodeString_to_ANSI(PCUNICODE_STRING Input_Unicode, PCHAR* AnsiString, ULONG32* AnsiStringMaxLength);
				VOID Release_UnicodeString_to_ANSI(PCHAR allocated_string);
			}
			
		}
	}
	
}

#endif