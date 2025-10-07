#ifndef HELPER_HPP
#define HELPER_HPP

#include "../hash/hash.hpp"
#include <fstream>  // 파일 입출력
#include <vector>
#include <ostream>
#include <pwd.h>
#include <grp.h>
#include <sys/utsname.h>

// C 스타일 파일 I/O 및 에러 처리를 위한 헤더
#include <unistd.h>      // for read(), lseek(), close()
#include <fcntl.h>       // for open()
#include <cerrno>        // for errno
#include <cstring>       // for strerror()
#include <sys/types.h>   // for off_t

#include "../json.hpp"

namespace EDR
{
    namespace Util
    {
        namespace Helper
        {
            

            inline std::string reversePath(const std::string& reversedPath) {
                // 1. 입력 문자열을 파싱하기 위해 stringstream을 사용합니다.
                std::stringstream ss(reversedPath);
                std::string component;
                std::vector<std::string> components;

                // 2. '/'를 기준으로 문자열을 분리하여 vector에 저장합니다.
                while (std::getline(ss, component, '/')) {
                    components.push_back(component);
                }

                // 3. vector를 거꾸로 순회하며 새로운 경로 문자열을 만듭니다.
                std::string correctPath = "/"; // 맨앞에 먼저 슬래시 추가해야함 안하면 상대경로됨
                // rbegin()과 rend()는 vector를 거꾸로 순회하는 반복자(iterator)입니다.
                for (auto it = components.rbegin(); it != components.rend(); ++it) {
                    correctPath += *it;
                    // 마지막 요소가 아니면 '/'를 추가합니다.
                    if (std::next(it) != components.rend()) {
                        correctPath += "/";
                    }
                }

                return correctPath;
            }

            // char -> string 시 중간에 "\0" 이 있어도 짤리지 않고, 길이를 알고 있을 때 그대로 복사 ( \0를 만나면 공란처리 )
            inline std::string forceCopyString(unsigned char* buf, __u32 buf_len)
            {
                if (!buf || buf_len == 0) {
                    return std::string();
                }

                // raw memory 그대로 std::string에 복사
                std::string raw_cmdline(reinterpret_cast<char*>(buf), buf_len);

                // \0 → ' ' 치환
                for (auto &c : raw_cmdline) {
                    if (c == '\0') {
                        c = ' ';
                    }
                }

                // trim: 끝에 붙는 불필요한 공백 제거
                while (!raw_cmdline.empty() && raw_cmdline.back() == ' ') {
                    raw_cmdline.pop_back();
                }

                return raw_cmdline;
            }

            inline void filepath_head_slash_insert_if_not( std::string& FilePath)
            {
                if(!FilePath.empty() || FilePath.front() != '/')
                    FilePath.insert(0, "/");
            }
            // file 디스크립터 to SHA256
            inline std::string FD_to_SHA256(int fd)
            {
                // 1. 유효하지 않은 파일 디스크립터 확인
                if (fd < 0) {
                    std::cerr << "FD_to_SHA256 Error: Invalid file descriptor provided." << std::endl;
                    return "";
                }

                try {
                    // 2. 현재 파일 오프셋(읽기 위치) 저장 (함수 종료 시 복원을 위해)
                    off_t original_offset = lseek(fd, 0, SEEK_CUR);
                    if (original_offset == (off_t)-1) {
                        perror("FD_to_SHA256 Error: lseek (getting current position) failed");
                        return "";
                    }

                    // 3. 파일의 맨 처음으로 오프셋 이동
                    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
                        perror("FD_to_SHA256 Error: lseek (rewinding to start) failed");
                        // 복원할 필요 없이 바로 종료
                        return "";
                    }

                    // --- 여기서부터는 기존 로직과 유사 ---

                    // SHA-256 컨텍스트 초기화
                    SHA256_CTX ctx;
                    SHA256_Init(&ctx);

                    // 청크 단위로 파일 읽고 해시 계산
                    const size_t CHUNK_SIZE = 8192; // 8KB
                    std::vector<unsigned char> buffer(CHUNK_SIZE);
                    ssize_t bytesRead;

                    while ((bytesRead = read(fd, buffer.data(), buffer.size())) > 0) {
                        SHA256_Update(&ctx, buffer.data(), bytesRead);
                    }

                    // read 함수에서 에러가 발생했는지 확인 (0은 파일 끝, -1은 에러)
                    if (bytesRead == -1) {
                        perror("FD_to_SHA256 Error: read failed");
                        lseek(fd, original_offset, SEEK_SET); // 에러 발생 시에도 위치 복원 시도
                        return "";
                    }

                    // 최종 해시값 계산
                    unsigned char hash[SHA256_DIGEST_LENGTH];
                    SHA256_Final(hash, &ctx);

                    // 4. (매우 중요) 파일 오프셋을 원래 위치로 복원
                    if (lseek(fd, original_offset, SEEK_SET) == (off_t)-1) {
                        // 해시는 성공했지만 복원에 실패한 경우, 경고 메시지를 출력할 수 있음
                        perror("FD_to_SHA256 Warning: Failed to restore original file offset");
                    }
                    
                    // 해시를 16진수 문자열로 변환
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0');
                    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                        oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
                    }

                    return oss.str();
                }
                catch (const std::exception& e) {
                    std::cerr << "FD_to_SHA256 Exception: " << e.what() << std::endl;
                    return "";
                }
            }

            // File Path to SHA256
            inline std::string FilePath_to_SHA256(const std::string& FilePath )
            {
                try
                {
                    // 파일 열기
                    std::ifstream file(FilePath, std::ios::binary | std::ios::ate);
                    if (!file.is_open())
                    {
                        std::cerr << "파일을 열 수 없습니다: " << FilePath << std::endl;
                        return "";
                    }

                    // 파일 크기 구하기
                    //output_fileSize = file.tellg();
                    file.seekg(0, std::ios::beg);

                    // SHA-256 컨텍스트 초기화
                    SHA256_CTX ctx;
                    SHA256_Init(&ctx);

                    // 청크 단위로 파일 읽고 해시 계산
                    std::vector<char> buffer(EDR::Util::hash::CHUNK_SIZE);
                    while (file)
                    {
                        file.read(buffer.data(), buffer.size());
                        std::streamsize bytesRead = file.gcount();
                        
                        if (bytesRead > 0)
                        {
                            SHA256_Update(&ctx, reinterpret_cast<const unsigned char*>(buffer.data()), bytesRead);
                        }
                    }

                    file.close();

                    // 최종 해시값 계산
                    unsigned char hash[SHA256_DIGEST_LENGTH];
                    SHA256_Final(hash, &ctx);

                    // 해시를 16진수 문자열로 변환
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0');
                    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                    {
                        oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
                    }

                    return oss.str();
                }
                catch (const std::exception& e)
                {
                    std::cerr << "FilePath_to_SHA256 에러: " << e.what() << std::endl;
                    return "";
                }
            }

            namespace UIDGID
            {
                inline std::string uid_to_name(uid_t uid) {
                    struct passwd *pw = getpwuid(uid);
                    if (pw)
                        return std::string(pw->pw_name);
                    return std::to_string(uid); // 없으면 숫자 반환
                }

                inline std::string gid_to_name(gid_t gid) {
                    struct group *gr = getgrgid(gid);
                    if (gr)
                        return std::string(gr->gr_name);
                    return std::to_string(gid); // 없으면 숫자 반환
                }
            }

            namespace hardware
            {
                // SMBIOS Type 1 (System Information) 데이터를 저장할 구조체
                struct SystemInfo {
                    std::string manufacturer;
                    std::string productName;
                    std::string version;
                    std::string serialNumber;
                    std::string uuid;
                };

                // SMBIOS Type 2 (Baseboard Information) 데이터를 저장할 구조체
                struct BaseboardInfo {
                    std::string manufacturer;
                    std::string productName;
                    std::string version;
                    std::string serialNumber;
                    std::string assetTag;
                };

                inline std::string readSysfsFile(const std::string& path) {
                    std::ifstream file(path);
                    if (!file.is_open()) {
                        return "Not Available";
                    }
                    std::string content;
                    std::getline(file, content);
                    // 파일 끝에 개행 문자가 있을 수 있으므로 제거
                    if (!content.empty() && content.back() == '\n') {
                        content.pop_back();
                    }
                    return content;
                }

                std::pair<SystemInfo, BaseboardInfo> getSmbiosSystemAndBoardInfo() {
                    const std::string basePath = "/sys/class/dmi/id/";
                    
                    SystemInfo sysInfo;
                    BaseboardInfo boardInfo;

                    // --- 타입 1: 시스템 정보 조회 ---
                    sysInfo.manufacturer = readSysfsFile(basePath + "sys_vendor");
                    sysInfo.productName  = readSysfsFile(basePath + "product_name");
                    sysInfo.version      = readSysfsFile(basePath + "product_version");
                    sysInfo.serialNumber = readSysfsFile(basePath + "product_serial");
                    sysInfo.uuid         = readSysfsFile(basePath + "product_uuid");

                    // --- 타입 2: 베이스보드 정보 조회 ---
                    boardInfo.manufacturer = readSysfsFile(basePath + "board_vendor");
                    boardInfo.productName  = readSysfsFile(basePath + "board_name");
                    boardInfo.version      = readSysfsFile(basePath + "board_version");
                    boardInfo.serialNumber = readSysfsFile(basePath + "board_serial");
                    boardInfo.assetTag     = readSysfsFile(basePath + "board_asset_tag");

                    return {sysInfo, boardInfo};
                }

                inline std::string Get_Hardware_hash()
                {
                    auto [system, board] = getSmbiosSystemAndBoardInfo();

                    std::ostringstream hardware_s;
                    hardware_s << system.manufacturer << system.productName << system.serialNumber << system.uuid << system.version << std::endl;
                    hardware_s << board.assetTag << board.manufacturer << board.productName << board.serialNumber << board.version << std::endl;

                    std::string hardware = hardware_s.str();
                    

                    return EDR::Util::hash::sha256FromString(hardware);
                }

                inline std::string get_sys_version()
                {
                    struct utsname u; 
                    uname(&u); 
                    //std::cout << u.sysname << " " << u.release << std::endl;

                    return u.release;
                }
            }

        }
    }
}

#endif