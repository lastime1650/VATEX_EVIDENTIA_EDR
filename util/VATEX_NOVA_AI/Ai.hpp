#ifndef VATEX_NOVA_AI_HPP
#define VATEX_NOVA_AI_HPP

#include <fmt/format.h>
#include "../httplib.h"
#include "../json.hpp"
using namespace nlohmann;

namespace EDR
{
    namespace Util
    {
        namespace AI
        {

            namespace AI_Query
            {
                namespace MachineLearning
                {
                    struct Datas
                    {

                    };

                    struct Train
                    {

                    };
                }

                namespace DeepLearning
                {
                    struct Datas
                    {
                        
                    };

                    struct Train
                    {
                        
                    };
                }


                class AI_ML_Train_Query
                {
                    public:
                        
                    private:
                        std::string id;
                };
            }
            

            constexpr char* Train_ML_Path = "/api/solution/util/nova/ML/train";
            constexpr char* Predict_ML_Path = "/api/solution/util/nova/ML/predict";


            class VATEX_NOVE_AI
            {
                public:
                    VATEX_NOVE_AI(
                        std::string server_ip = "127.0.0.1", // same endpoint
                        unsigned int server_port = 10302
                    ): Requester(server_ip, server_port)
                    {}
                    ~VATEX_NOVE_AI() = default;

                    template <typename T>
                    bool Train_ML(T& query)
                    {

                        try{
                            auto result = Request_Post(Train_ML_Path, query);
                            return true;
                        }
                        catch (const std::exception& e) {
                            std:: cout << e.what();
                            return false;
                        }
                        
                        
                    }

                    template <typename T>
                    bool Predict_ML(T& query)
                    {
                        try{
                            auto result = Request_Post(Predict_ML_Path, query);
                            return true;
                        }
                        catch (const std::exception& e) {
                            std:: cout << e.what();
                            return false;
                        }
                    }

                private:
                    httplib::Client Requester;

                    template <typename T>
                    json Request_Post(const std::string Path , const T& input)
                    {

                        std::string data; 

                        if constexpr (std::is_same_v<T, std::string> )
                        {
                            data = input;
                        }
                        else if constexpr (std::is_same_v<T, json> )
                        {
                            data = input.dump();
                        }
                        else
                            throw std::runtime_error( "Unknown Type T" );
                        
                        
                        auto response = Requester.Post(
                            Path,
                            data,
                            "application/json"
                        );

                        if(response->status != 200)
                            throw std::runtime_error( "VATEX_NOVA_AI returned not 200 status" );
                        std::cout << response->body;
                        auto ai_response = json::parse(response->body);
                        
                        if(!ai_response.contains("status") || ai_response["status"].get<bool>() == false)
                            throw std::runtime_error(  "No 'status' key in ai_response  OR Failed " );

                        return ai_response; 
                    }
            };
        }
    }
}

#endif