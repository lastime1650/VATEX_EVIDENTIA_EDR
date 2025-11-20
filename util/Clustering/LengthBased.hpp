#ifndef LENGTHBASED_MESSAGE_HPP
#define LENGTHBASED_MESSAGE_HPP

#include <vector>
#include <iostream>

namespace EDR
{
    namespace Util
    {
        namespace LengthBase
        {
            struct ParsedData
            {
                std::vector<unsigned char> Head;
                std::vector<  std::vector<unsigned char>  > Datas;
            };

            // 역직렬화
            ParsedData Parsing_Data(std::vector<unsigned char> Buffer)
            {
                if(Buffer.empty())
                    throw std::runtime_error("Buffer is Empty !!");

                if(Buffer.size() < 4)
                    throw std::runtime_error("Buffer is less than 4 bytes !!");

                ParsedData result;
                
                unsigned long long current_index = 0;

                // 1. 처음 4바이트 (Head 읽기)
                result.Head.assign( Buffer.begin(), Buffer.begin()+4 ); // [0:4]
                current_index += 4;

                // 2. while문 순회
                while (current_index < Buffer.size())
                {
                    if (current_index + 4 > Buffer.size())
                        throw std::runtime_error("Invalid buffer: incomplete length field");

                    std::vector<unsigned char> Data_Length_by_Vec;
                    unsigned int Data_Length_by_uint = 0;

                    std::vector<unsigned char> Data;

                    // 1. 4바이트 고정
                    Data_Length_by_Vec.assign( Buffer.begin()+current_index, (Buffer.begin()+current_index)+4 );
                    current_index+=4;

                    Data_Length_by_uint = *reinterpret_cast<unsigned int*>(Data_Length_by_Vec.data());

                    // 2. (1)에서 구한 길이만큼 읽기
                    if (current_index + Data_Length_by_uint > Buffer.size())
                        throw std::runtime_error("Invalid buffer: data length exceeds buffer size");

                    Data.assign( Buffer.begin()+current_index,  (Buffer.begin()+current_index) + Data_Length_by_uint  );
                    current_index+= Data_Length_by_uint;

                    result.Datas.emplace_back(   std::move(Data)    );
                }
                

                return result;
            }

            // 직렬화
            std::vector<unsigned char> BufferParsing_Data(const ParsedData& source)
            {
                std::vector<unsigned char> Buffer;

                // 1. Head (4바이트)
                if (source.Head.size() != 4)
                    throw std::runtime_error("Head must be 4 bytes");

                Buffer.insert(Buffer.end(), source.Head.begin(), source.Head.end());

                // 2. Datas 순회
                for (const auto& data : source.Datas)
                {
                    // 2-1. 데이터 길이 (4바이트, 리틀엔디안)
                    unsigned int len = static_cast<unsigned int>(data.size());
                    const unsigned char* pLen = reinterpret_cast<const unsigned char*>(&len);
                    Buffer.insert(Buffer.end(), pLen, pLen + sizeof(len));

                    // 2-2. 데이터 내용
                    Buffer.insert(Buffer.end(), data.begin(), data.end());
                }

                return Buffer;
            }

        }
    }
}
#endif