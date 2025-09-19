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

				// 1. 입력된 std::string(UTF-8 또는 멀티바이트)을 유니코드(std::wstring)로 변환합니다.
				//    Windows API인 ConvertStringSidToSidW는 유니코드 문자열(LPCWSTR)을 인자로 받습니다.
				int wideCharSize = MultiByteToWideChar(CP_UTF8, 0, sid.c_str(), -1, NULL, 0);
				if (wideCharSize == 0)
				{
					return FALSE;
				}
				std::wstring wideSid(wideCharSize, 0);
				MultiByteToWideChar(CP_UTF8, 0, sid.c_str(), -1, &wideSid[0], wideCharSize);
				wideSid.resize(wcslen(wideSid.c_str())); // Null terminator에 의한 여분 공간 제거

				// 2. 문자열 SID를 바이너리 형태의 SID (PSID)로 변환합니다.
				//    이 함수는 pSid에 대한 메모리를 할당하므로, 나중에 반드시 LocalFree로 해제해야 합니다.
				if (!ConvertStringSidToSidW(wideSid.c_str(), &pSid))
				{
					return FALSE;
				}

				DWORD nameSize = 0;
				DWORD domainSize = 0;
				SID_NAME_USE sidUse;

				// 3. 사용자 이름과 도메인 이름을 조회합니다. (첫 번째 호출: 필요한 버퍼 크기 확인)
				LookupAccountSidW(NULL, pSid, NULL, &nameSize, NULL, &domainSize, &sidUse);

				// 버퍼가 부족하다는 오류가 아니면, 다른 문제이므로 실패 처리합니다.
				if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				{
					LocalFree(pSid); // ★ 메모리 해제
					return FALSE;
				}

				// 4. 알아낸 크기만큼 버퍼를 할당합니다.
				std::wstring nameBuffer(nameSize, 0);
				std::wstring domainBuffer(domainSize, 0);

				// 5. 사용자 이름과 도메인 이름을 다시 조회합니다. (두 번째 호출: 실제 데이터 가져오기)
				if (!LookupAccountSidW(NULL, pSid, &nameBuffer[0], &nameSize, &domainBuffer[0], &domainSize, &sidUse))
				{
					LocalFree(pSid); // ★ 메모리 해제
					return FALSE;
				}

				// 6. 사용이 끝난 PSID 메모리를 반드시 해제합니다.
				LocalFree(pSid);

				// 버퍼 크기에서 null terminator를 제외하여 실제 문자열로 만듭니다.
				nameBuffer.resize(nameSize);
				domainBuffer.resize(domainSize);

				// 7. 도메인 이름과 사용자 이름을 "DOMAIN\Username" 형식으로 조합합니다.
				std::wstring finalUsername;
				if (!domainBuffer.empty())
				{
					finalUsername = domainBuffer + L"\\" + nameBuffer;
				}
				else
				{
					finalUsername = nameBuffer; // 로컬 계정이나 시스템 계정 등
				}

				// 8. 최종 결과인 유니코드 사용자 이름을 다시 std::string(UTF-8)으로 변환하여 출력합니다.
				int bufferSize = WideCharToMultiByte(CP_UTF8, 0, finalUsername.c_str(), -1, NULL, 0, NULL, NULL);
				if (bufferSize == 0)
				{
					return FALSE;
				}

				username.resize(bufferSize - 1); // null terminator 제외
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

				while (ptr + 2 <= end) { // 최소 2바이트 이상 남았는지 확인
					BYTE type = ptr[0];
					BYTE length = ptr[1];

					// 구조체 끝 포인터 계산
					BYTE* structEnd = ptr + length;
					if (structEnd > end) break; // 버퍼 넘어가면 종료

					// 문자열 영역 시작
					BYTE* stringArea = structEnd;

					// 문자열 영역 끝 찾기 (0x00 0x00)
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

					ptr = strEnd; // 다음 구조체로 이동
				}

				return result;
			}


		}
	}
}