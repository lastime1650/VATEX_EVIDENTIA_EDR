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
            private:
                EDR::Server::EDRServer& EDR_Backend;

            public:
            
                APIServer(
                    std::string APIServerIP, 
                    unsigned int APIServerPORT,
                    
                    // EDR Backend
                    EDR::Server::EDRServer& EDR_Backend
                ) : 
                APIServerIP(APIServerIP), 
                APIServerPORT(APIServerPORT),

                EDR_Backend(EDR_Backend)
                {
                    // httplib 기반 API서버
                    
                    
                }
                ~APIServer();


                bool Runner()
                {
                    if(is_working)
                        return false;

                    is_working= true;

                    // ==================================================

                    // 1. Query
                    // -> 1.A. Live_Data (Solution Depend)
                    // -> 2.A. Serve

                    // 2. Response
                    // -> 2.A. File
                    // -> 2.B. Process
                    // -> 2.C. Network

                    // ==================================================



                    // Blocking ... ( 맨 마지막에 실행해야 한다.)

                }

                bool Run(){
                    if(is_working)
                        return false;
                    
                    is_working= true;
                    std::thread(
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
                                        => 5.3. /api/solution/edr/query/event/original
                                        => 5.4. /api/solution/edr/query/event/mitre_attack
                                        => 5.5. /api/soultion/edr/query/event/association
                                ===========================================================

                                ===========================================================
                                2. Policy       타입
                                    => 1. /api/solution/edr/policy/add ( 룰은 올인원으로 변경됨 )
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
                                "/api/solution/edr/query/agent",
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

                                    success_result_output = this->EDR_Backend.AgentTCPManager.Get_Information(); 
                                    
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

                                    /* no parameters */
                                    
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////
                                    /*
                                        <output>
                                        {
                                            "agents": {
                                                "AGENT_ID-1": {
                                                    "is_alive": true,
                                                    "ipv4": ...,
                                                    "port": ...
                                                }
                                            },
                                        }
                                    */

                                    std::string fail_reason = "";
                                    json success_result_output;

                                    success_result_output = this->EDR_Backend.AgentTCPManager.Get_Information(); 
                                    
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


                            /* << Policy >> */
                            this->APIsvr.Post(
                                "/api/solution/edr/policy/add",
                                [this](const httplib::Request& req, httplib::Response& res)
                                {
                                    /*
                                        인 메모리 룰 등록
                                    */
                                    /*
                                        {
                                            // Rule Keys... id to filename
                                        }
                                    */
                                    req.body;
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////
                                    /////////////////////////////////////////////////////////////////////////
                                }
                            );

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

                                        REQ_JSON = this->_text_to_json(req.body);

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
                                    if ( !this->EDR_Backend.AgentTCPManager.findAgent(AgentId) )
                                    {
                                        fail_reason = "No Running Agent";
                                        goto FAIL;
                                    }

                                    // 2. Request Process Request
                                    if ( !this->EDR_Backend.AgentTCPManager.Response_PROCESS(AgentId, pid, exe_path) )
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
                                        
                                        REQ_JSON = this->_text_to_json(req.body);

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
                                    if ( !this->EDR_Backend.AgentTCPManager.findAgent(AgentId) )
                                    {
                                        fail_reason = "No Running Agent";
                                        goto FAIL;
                                    }

                                    // 2. Request Process Request
                                    if ( !this->EDR_Backend.AgentTCPManager.Response_FILE(AgentId, file_path) )
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

                std::atomic<bool> is_working = false;

                // helper
                
                // 1. text to json
                json _text_to_json(const std::string Body)
                {
                    try
                    {
                        return json::parse(Body);
                    }
                    catch (const std::exception& e)
                    {
                        throw e.what();
                    }
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