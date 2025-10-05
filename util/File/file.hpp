#ifndef FILE_HANDLER_HPP
#define FILE_HANDLER_HPP

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>

namespace EDR
{
    namespace Util
    {
        namespace File
        {
            class FileHandler {
                public:
                    FileHandler() = default;

                    // 바이너리 파일 쓰기
                    bool writeToFile(const std::string& filename, const std::vector<uint8_t>& data, bool append = false) {
                        std::ofstream outFile;
                        if (append)
                            outFile.open(filename, std::ios::binary | std::ios::app);
                        else
                            outFile.open(filename, std::ios::binary | std::ios::trunc);

                        if (!outFile.is_open()) {
                            std::cerr << "파일 열기 실패: " << filename << std::endl;
                            return false;
                        }

                        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
                        outFile.close();
                        return true;
                    }

                    // 바이너리 파일 읽기
                    std::vector<uint8_t> readFromFile(const std::string& filename) {
                        std::ifstream inFile(filename, std::ios::binary);
                        std::vector<uint8_t> data;

                        if (!inFile.is_open()) {
                            std::cerr << "파일 열기 실패: " << filename << std::endl;
                            return data;
                        }

                        inFile.seekg(0, std::ios::end);
                        std::streamsize size = inFile.tellg();
                        inFile.seekg(0, std::ios::beg);

                        if (size > 0) {
                            data.resize(size);
                            inFile.read(reinterpret_cast<char*>(data.data()), size);
                        }

                        inFile.close();
                        return data;
                    }
                };
        }
    }
}


#endif // FILE_HANDLER_HPP
