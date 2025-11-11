#ifndef APISERVER_HPP
#define APISERVER_HPP

#include "../../util/util.hpp"

#include "../util/ServerUtil.hpp"
#include "../EDRServer.hpp"
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
                    unsigned int APIServerPORT,
                    
                    // instances
                    EDR::Server::AgentTcpManagement::AgentTcp& AGENT_TCP
                ) : 
                APIServerIP(APIServerIP), 
                APIServerPORT(APIServerPORT),

                AGENT_TCP(AGENT_TCP)
                {
                    // httplib 기반 API서버
                    
                    
                }
                ~APIServer();

                bool Run(){
                    if(is_working)
                        return false;
                    
                    is_working= true;
                    API_SERVER_THREAD = std::thread(
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
                                    => 5. /api/solution/edr/query/event                             -> all
                                        => EDR솔루션에서 "수집된" 이벤트 쿼리
                                        => 5.1. /api/solution/edr/query/event/trees                 -> 특정 Agentid 로 tree 조회 ( id 조회 )
                                        => 5.2. /api/solution/edr/query/event/tree/detail           -> 특정 Agentid, 특정 tree 에 대한 이벤트 반환 ( tree에 저장된 이벤트 조회 )
                                        => 5.3. /api/solution/edr/query/event/original
                                        => 5.4. /api/solution/edr/query/event/mitre_attack
                                        => 5.5. /api/soultion/edr/query/event/association
                                ===========================================================

                                ===========================================================
                                2. Policy       타입
                                    => 1. /api/solution/edr/policy/add/mitre_attack
                                        =>? EDR솔루션 정책 중. <<마이터 어택 연동 룰>> 관리
                                    => 2. /api/solution/edr/policy/add/association
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

                            /*
                                << Query >>
                            */
                            //  - "/api/solution/edr/query/event"
                            // 1. 
                            this->APIsvr.Get(
                                "/api/solution/edr/query/event",
                                [this](const httplib::Request& req, httplib::Response& res)
                                {
                                    /*
                                        event 전체 조회 임
                                    */
                                    /*
                                        {
                                            // 방대한 이벤트량을 제한하기 위해선 나노스탬프 키값은 필수임 (event 류 쿼리 전체에 해당)
                                            "timestamp" : {
                                                "start_nanostamp" : 0000,
                                                "last_nanostamp"  : 0000
                                            },
                                            "agentid" : "..." // [Optional] key. 만약 key 설정없으면 에이전트 전체. 다 가져옴
                                            
                                        }
                                    */
                                    // variables
                                    unsigned long long start_nanostamp = 0;
                                    unsigned long long last_nanostamp = 0;
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////


                                    std::string fail_reason = "";
                                    json success_result_output;

                                    success_result_output = this->AGENT_TCP.Get_Information(); 
                                    
                                    SUCCESS:
                                    {
                                        this->set_success_response(success_result_output, res);
                                        return;
                                    }
                                    FAIL:
                                    {
                                        this->set_fail_response(fail_reason, res);
                                        return;
                                    }
                                }
                            );


                            //  - "/api/solution/edr/query/agent"
                            this->APIsvr.Get(
                                "/api/solution/edr/query/agent",
                                [this](const httplib::Request& req, httplib::Response& res)
                                {
                                    /*
                                        agent 전체 조회 임
                                    */
                                    
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////


                                    std::string fail_reason = "";
                                    json success_result_output;

                                    success_result_output = this->AGENT_TCP.Get_Information(); 
                                    
                                    SUCCESS:
                                    {
                                        this->set_success_response(success_result_output, res);
                                        return;
                                    }
                                    FAIL:
                                    {
                                        this->set_fail_response(fail_reason, res);
                                        return;
                                    }
                                }
                            );


                            // << Policy >>

                            /*
                                << Response >>
                            */ 
                            // 1. Process 
                            this->APIsvr.Get(
                                "/api/solution/edr/response/process",
                                [this](const httplib::Request& req, httplib::Response& res)
                                {

                                    /*
                                        프로세스 차단 요청
                                    */
                                    /*
                                        {
                                            "agentid" : "...."
                                            "pid": 0000,
                                            "exe_path"
                                        }
                                    */
                                    // variables
                                    std::string AgentId;
                                    unsigned long long pid;
                                    std::string exe_path;
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////


                                    std::string fail_reason = "";
                                    json success_result_output;

                                    json REQ_JSON;
                                    try{
                                        if( this->_text_to_json(req.body, REQ_JSON) )
                                            goto FAIL;

                                    }catch (const std::exception& e )
                                    {
                                        fail_reason = e.what();
                                        goto FAIL;
                                    }

                                    // key test
                                    if( !REQ_JSON.contains("agentid") || !REQ_JSON.contains("pid") || !REQ_JSON.contains("exe_path") )
                                    {
                                        fail_reason = "Wrong Key";
                                        goto FAIL;
                                    }

                                    // variables
                                    AgentId = REQ_JSON["agentid"].get<std::string>();
                                    pid = REQ_JSON["pid"].get<unsigned long long>();
                                    exe_path = REQ_JSON["exe_path"].get<std::string>();
                                    
                                    // 1. Check AgentId in Memory
                                    if ( !this->AGENT_TCP.findAgent(AgentId) )
                                    {
                                        fail_reason = "No Running Agent";
                                        goto FAIL;
                                    }

                                    // 2. Request Process Request
                                    if ( !this->AGENT_TCP.Response_PROCESS(AgentId, pid, exe_path) )
                                    {
                                        fail_reason = "Failed Response Process";
                                        goto FAIL;
                                    }

                                    // Result
                                    success_result_output = {
                                        {"reason", "Success Response Process"}
                                    };

                                    SUCCESS:
                                    {
                                        this->set_success_response(success_result_output, res);
                                        return;
                                    }
                                    FAIL:
                                    {
                                        this->set_fail_response(fail_reason, res);
                                        return;
                                    }
                                }
                            );
                            // 2. File
                            this->APIsvr.Get(
                                "/api/solution/edr/response/file",
                                [this](const httplib::Request& req, httplib::Response& res)
                                {

                                    /*
                                        프로세스 차단 요청
                                    */
                                    /*
                                        {
                                            "agentid" : "...."
                                            "file_path" : "...."
                                        }
                                    */
                                    // variables
                                    std::string AgentId;
                                    std::string file_path;
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////


                                    std::string fail_reason = "";
                                    json success_result_output;

                                    json REQ_JSON;
                                    try{
                                        if( this->_text_to_json(req.body, REQ_JSON) )
                                            goto FAIL;

                                    }catch (const std::exception& e )
                                    {
                                        fail_reason = e.what();
                                        goto FAIL;
                                    }

                                    // key test
                                    if( !REQ_JSON.contains("agentid") || !REQ_JSON.contains("file_path") )
                                    {
                                        fail_reason = "Wrong Key";
                                        goto FAIL;
                                    }

                                    // variables
                                    AgentId = REQ_JSON["agentid"].get<std::string>();
                                    file_path = REQ_JSON["file_path"].get<std::string>();
                                    
                                    // 1. Check AgentId in Memory
                                    if ( !this->AGENT_TCP.findAgent(AgentId) )
                                    {
                                        fail_reason = "No Running Agent";
                                        goto FAIL;
                                    }

                                    // 2. Request Process Request
                                    if ( !this->AGENT_TCP.Response_FILE(AgentId, file_path) )
                                    { 
                                        fail_reason = "Failed Response Process";
                                        goto FAIL;
                                    }

                                    // Result
                                    success_result_output = {
                                        {"reason", "Success Response Process"}
                                    };

                                    SUCCESS:
                                    {
                                        this->set_success_response(success_result_output, res);
                                        return;
                                    }
                                    FAIL:
                                    {
                                        this->set_fail_response(fail_reason, res);
                                        return;
                                    }
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


                std::thread API_SERVER_THREAD;
                std::atomic<bool> is_working = false;

                EDR::Server::AgentTcpManagement::AgentTcp& AGENT_TCP;

                // helper
                
                // 1. text to json
                bool _text_to_json(const std::string Body, json& output)
                {
                    try
                    {
                        output = json::parse(Body);
                        return true;
                    }
                    catch (const std::exception& e)
                    {
                        throw e.what();
                    }
                    return false;
                }

                 // 2. Failed JSON Output
                bool set_fail_response(std::string reason, httplib::Response& res)
                {
                    json body = {
                        {"status", false},
                        {"fail_reason", reason}
                    };

                    res.set_content(body.dump(), "application/json");

                    return true;
                }
                bool set_success_response(json output, httplib::Response& res)
                {
                    json body = {
                        {"status", true},
                        {"output", output}
                    };

                    res.set_content(body.dump(), "application/json");

                    return true;
                }
            };

           
        }
    }
}

#endif