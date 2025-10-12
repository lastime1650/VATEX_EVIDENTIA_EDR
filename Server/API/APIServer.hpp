#ifndef APISERVER_HPP
#define APISERVER_HPP

#include "../../util/util.hpp"

#include "../util/ServerUtil.hpp"

namespace EDR
{
    namespace Server
    {
        namespace API
        {
            class APIServer
            {
            public:
            
                APIServer(
                    std::string APIServerIP, 
                    unsigned int APIServerPORT 
                ) : 
                APIServerIP(APIServerIP), 
                APIServerPORT(APIServerPORT)
                {
                    // httplib 기반 API서버
                    
                    
                }
                ~APIServer();

                bool Run(){
                    if(is_working)
                        return false;
                    
                    is_working= true;
                    API_HTTP_SERVER_THREAD = std::thread(
                        [this]()
                        {
                            /*
                                API 로직
                            */
                            /*
                                ===========================================================
                                1. Query        타입
                                    => 1. /api/solution/edr/query/all
                                        =>? EDR솔루션 쿼리가능정보 전체 반환
                                    => 2. /api/solution/edr/query/server_info
                                        =>? EDR솔루션 서버 정보 반환
                                    => 3. /api/solution/edr/query/agent
                                        =>? EDR솔루션 에이전트 정보 반환 (+라이브 현황)
                                    => 4. "/api/solution/edr/query/policy"
                                        => EDR솔루션에서 사용하는 정책 쿼리
                                    => 5. /api/solution/edr/query/event
                                        => EDR솔루션에서 "수집된" 이벤트 쿼리
                                ===========================================================

                                ===========================================================
                                2. Policy       타입
                                    => 1. /api/solution/edr/policy/add/mitre_attack
                                        =>? EDR솔루션 정책 중. <<마이터 어택 연동 룰>> 관리
                                    => 2. /api/solution/edr/policy/add/association_analyse
                                        =>? EDR솔루션 정책 중. <<연관 시나리오 분석 연동 룰>> 관리
                                ===========================================================

                                ===========================================================
                                3. Response     타입
                                    => 1. /api/solution/edr/response/process
                                    => 2. /api/solution/edr/response/network
                                    => 3. /api/solution/edr/response/file
                                ===========================================================

                            */

                            /*
                                Logic
                            */

                            // << Query >>
                            
                            // << Policy >>
                            // << Response >>
                            this->APIsvr.Get(
                                "/api/solution/edr/response/process",
                                [](const httplib::Request& req, httplib::Response& res)
                                {
                                    
                                }
                            );

                            this->APIsvr.listen(
                                this->APIServerIP,
                                this->APIServerPORT
                            );
                        }
                    );

                }
                bool Stop(){
                    if(!is_working)
                        return false;

                    is_working = false;
                    this->APIsvr.stop();

                    return true;
                }

            private:
                std::string APIServerIP;
                unsigned int APIServerPORT;

                httplib::Server APIsvr;


                std::thread API_HTTP_SERVER_THREAD;
                std::atomic<bool> is_working = false;

            };
        }
    }
}

#endif