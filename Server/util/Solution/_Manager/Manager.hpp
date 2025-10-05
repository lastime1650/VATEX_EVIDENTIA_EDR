// 보안솔루션 코어 추상 클래스

/*
    **필수 구현 기능
    0. Normal ( 전반적인 서버 정보 )
    1. Detection ( 분석  기능 ) -> Policy + Intelligence 및 AI 간 연동
    2. Response ( 차단 기능 )


    ** 별도로 정의해야하는 기능
    
    1. 로그 전처리 ( 이 후 Detection 호출 )

    *** 인자 (in, out)은 대부분 JSON타입으로 통일.
    
*/
#ifndef SOLUTION_MANAGER_HPP
#define SOLUTION_MANAGER_HPP

// 하위 요소
// 1. API
#include "httplib.h"
#include "API/_parent.hpp"

// 2. Intelligence
#include "Intelligence/intelligence.hpp"

// 3. Policy ( EDR )
#include "Policy/_Child/EDRPolicy.hpp"

#include <any>
#include <string>
#include "json.hpp"
using namespace nlohmann;

namespace Solution
{
    namespace Manager
    {
        
        namespace SolutionInfo
        {
            class SolutionInfo_Parent
            {
            public:
                SolutionInfo_Parent() = default;
                virtual ~SolutionInfo_Parent() = 0;

                virtual bool Get_Information( json& output ) = 0; // json포맷으로 통일 내부는 솔루션마다 다름

                struct
                {
                    std::string ServerIP;
                    unsigned int ServerPORT;
                }API_Server;

                struct
                {
                    std::string ServerIP;
                    unsigned int ServerPORT;
                }WEB_Server;
            };
        }


        // 보안솔루션 전반적인 코어 매니저
        
        namespace Parent
        {
            template<
                typename DetectionIn,
                typename DetectionOut,
                typename Request_IntelligenceIn,
                typename Request_IntelligenceOut,
                typename ResponseIn

            >
            class SolutionManager
            {
            protected:
                SolutionManager(

                    /*
                        VATEX INTELLINA INTELLIGENCE API 연결정보
                    */
                    std::string VATEX_INTELLINA_API_ServerIp,
                    unsigned int VATEX_INTELLINA_API_ServerPort = 51034
                )
                : VATEX_INTELLINA(VATEX_INTELLINA_API_ServerIp, VATEX_INTELLINA_API_ServerPort)
                {}
                virtual ~SolutionManager() = 0;

                // Detection 기능 ( 최종분석용으로 사용 ) 
                virtual bool Detection( const DetectionIn& input, DetectionOut& output ) = 0;

                // Response 차단 기능 
                virtual bool Response( const ResponseIn& input ) = 0;
                virtual bool UnResponse( const ResponseIn& input ) = 0;

                // 실시간 서버 정보 전체 반환
                virtual bool Get_Solution_Information( SolutionInfo::SolutionInfo_Parent& output ) = 0;

                // 인텔리전스 멤버 (솔루션 매니저 멤버)
                Solution::Intelligence::Intellina VATEX_INTELLINA;
            };
        }

        // 솔루션 전반적인 정보를 나타내는 부모 클래스
        /*
            솔루션이 공유하거나, 전체적으로 기억해야하는 모든 부분을 해당 구조체에 모두 담아야한다.
            // ex) EDR의 경우, 에이전트 기록을 모두 여기에 담아야한다 또한 별도로 에이전트를 관리하는 스레드 및 클래스를 구현해야한다. 
        */
        
    }
}

#endif