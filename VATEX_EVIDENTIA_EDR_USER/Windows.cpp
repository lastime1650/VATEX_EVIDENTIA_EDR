#include "Windows.hpp"

namespace EDR
{
	namespace Util
	{
		namespace Windows
		{
			BOOLEAN SID_to_Username(std::string sid, std::string& username)
			{
				PSID pSid = NULL;

				// 1. �Էµ� std::string(UTF-8 �Ǵ� ��Ƽ����Ʈ)�� �����ڵ�(std::wstring)�� ��ȯ�մϴ�.
				//    Windows API�� ConvertStringSidToSidW�� �����ڵ� ���ڿ�(LPCWSTR)�� ���ڷ� �޽��ϴ�.
				int wideCharSize = MultiByteToWideChar(CP_UTF8, 0, sid.c_str(), -1, NULL, 0);
				if (wideCharSize == 0)
				{
					return FALSE;
				}
				std::wstring wideSid(wideCharSize, 0);
				MultiByteToWideChar(CP_UTF8, 0, sid.c_str(), -1, &wideSid[0], wideCharSize);
				wideSid.resize(wcslen(wideSid.c_str())); // Null terminator�� ���� ���� ���� ����

				// 2. ���ڿ� SID�� ���̳ʸ� ������ SID (PSID)�� ��ȯ�մϴ�.
				//    �� �Լ��� pSid�� ���� �޸𸮸� �Ҵ��ϹǷ�, ���߿� �ݵ�� LocalFree�� �����ؾ� �մϴ�.
				if (!ConvertStringSidToSidW(wideSid.c_str(), &pSid))
				{
					return FALSE;
				}

				DWORD nameSize = 0;
				DWORD domainSize = 0;
				SID_NAME_USE sidUse;

				// 3. ����� �̸��� ������ �̸��� ��ȸ�մϴ�. (ù ��° ȣ��: �ʿ��� ���� ũ�� Ȯ��)
				LookupAccountSidW(NULL, pSid, NULL, &nameSize, NULL, &domainSize, &sidUse);

				// ���۰� �����ϴٴ� ������ �ƴϸ�, �ٸ� �����̹Ƿ� ���� ó���մϴ�.
				if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				{
					LocalFree(pSid); // �� �޸� ����
					return FALSE;
				}

				// 4. �˾Ƴ� ũ�⸸ŭ ���۸� �Ҵ��մϴ�.
				std::wstring nameBuffer(nameSize, 0);
				std::wstring domainBuffer(domainSize, 0);

				// 5. ����� �̸��� ������ �̸��� �ٽ� ��ȸ�մϴ�. (�� ��° ȣ��: ���� ������ ��������)
				if (!LookupAccountSidW(NULL, pSid, &nameBuffer[0], &nameSize, &domainBuffer[0], &domainSize, &sidUse))
				{
					LocalFree(pSid); // �� �޸� ����
					return FALSE;
				}

				// 6. ����� ���� PSID �޸𸮸� �ݵ�� �����մϴ�.
				LocalFree(pSid);

				// ���� ũ�⿡�� null terminator�� �����Ͽ� ���� ���ڿ��� ����ϴ�.
				nameBuffer.resize(nameSize);
				domainBuffer.resize(domainSize);

				// 7. ������ �̸��� ����� �̸��� "DOMAIN\Username" �������� �����մϴ�.
				std::wstring finalUsername;
				if (!domainBuffer.empty())
				{
					finalUsername = domainBuffer + L"\\" + nameBuffer;
				}
				else
				{
					finalUsername = nameBuffer; // ���� �����̳� �ý��� ���� ��
				}

				// 8. ���� ����� �����ڵ� ����� �̸��� �ٽ� std::string(UTF-8)���� ��ȯ�Ͽ� ����մϴ�.
				int bufferSize = WideCharToMultiByte(CP_UTF8, 0, finalUsername.c_str(), -1, NULL, 0, NULL, NULL);
				if (bufferSize == 0)
				{
					return FALSE;
				}

				username.resize(bufferSize - 1); // null terminator ����
				WideCharToMultiByte(CP_UTF8, 0, finalUsername.c_str(), -1, &username[0], bufferSize, NULL, NULL);

				return TRUE;
			}

			std::string ReadSMBIOSType1And2() {
				DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
				if (size == 0) return {};

				std::vector<BYTE> buffer(size);
				size = GetSystemFirmwareTable('RSMB', 0, buffer.data(), size);

				BYTE* ptr = buffer.data();
				BYTE* end = ptr + size;

				std::string result;

				auto getSMBIOSString = [](BYTE* strArea, BYTE index) -> std::string {
					if (index == 0) return {};
					char* s = reinterpret_cast<char*>(strArea);
					while (index > 1 && *s) {
						s += strlen(s) + 1;
						--index;
					}
					return std::string(s);
					};

				while (ptr + 2 <= end) { // �ּ� 2����Ʈ �̻� ���Ҵ��� Ȯ��
					BYTE type = ptr[0];
					BYTE length = ptr[1];

					// ����ü �� ������ ���
					BYTE* structEnd = ptr + length;
					if (structEnd > end) break; // ���� �Ѿ�� ����

					// ���ڿ� ���� ����
					BYTE* stringArea = structEnd;

					// ���ڿ� ���� �� ã�� (0x00 0x00)
					BYTE* strEnd = stringArea;
					while (strEnd + 1 < end) {
						if (strEnd[0] == 0 && strEnd[1] == 0) { strEnd += 2; break; }
						++strEnd;
					}

					if (type == 1 && length >= 8) { // System Information
						BYTE manuIdx = ptr[4];
						BYTE prodIdx = ptr[5];
						BYTE versionIdx = ptr[6];
						BYTE serialIdx = ptr[7];

						result += "SMBIOS Type 1:\n";
						result += " Manufacturer: " + getSMBIOSString(stringArea, manuIdx) + "\n";
						result += " Product: " + getSMBIOSString(stringArea, prodIdx) + "\n";
						result += " Version: " + getSMBIOSString(stringArea, versionIdx) + "\n";
						result += " Serial: " + getSMBIOSString(stringArea, serialIdx) + "\n";
					}
					else if (type == 2 && length >= 7) { // Base Board
						BYTE manuIdx = ptr[4];
						BYTE prodIdx = ptr[5];
						BYTE serialIdx = ptr[6];

						result += "SMBIOS Type 2:\n";
						result += " Manufacturer: " + getSMBIOSString(stringArea, manuIdx) + "\n";
						result += " Product: " + getSMBIOSString(stringArea, prodIdx) + "\n";
						result += " Serial: " + getSMBIOSString(stringArea, serialIdx) + "\n";
					}

					ptr = strEnd; // ���� ����ü�� �̵�
				}

				return result;
			}


		}
	}
}