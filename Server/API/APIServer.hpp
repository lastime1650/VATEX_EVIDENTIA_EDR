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
            
                APIServer( std::string APIServerIP, unsigned int APIServerPORT ) : APIServerIP(APIServerIP), APIServerPORT(APIServerPORT)
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