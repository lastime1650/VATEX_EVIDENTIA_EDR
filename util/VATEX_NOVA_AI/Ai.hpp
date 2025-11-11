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
                namespace WithId
                {
                    //{"nano_timestamp":1762759823874624737,"nano_timestamp_iso8901":"2025-11-10T16:30:23.874624737Z","at_samples_x_count":4,"train_result":{"type":"ML","output":1.0}
                    struct status_history
                    {
                        unsigned long long nano_timestamp;
                        std::string nano_timestamp_iso8901;
                        unsigned long long at_samples_x_count;
                        json train_result;
                    };

                    struct Status
                    {
                        unsigned long long samples_x_count;

                        std::vector<status_history> train_history;
                        std::vector<status_history> predict_history;

                        std::optional< std::vector<json> > detail = std::nullopt;

                    };
                }
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

            // WithId
            constexpr char* WithId_Sample_Push_Path = "/api/solution/util/nova/with_id/sample/push";
            constexpr char* WithId_Sample_y_Edit_Path = "/api/solution/util/nova/with_id/sample/y/edit";
            constexpr char* WithId_Sample_x_Edit_Path = "/api/solution/util/nova/with_id/sample/x/edit";
            constexpr char* WithId_Sample_Remove_Path = "/api/solution/util/nova/with_id/sample/remove";
            constexpr char* WithId_Train_ML_Path = "/api/solution/util/nova/with_id/ML/train";
            constexpr char* WithId_Predict_ML_Path = "/api/solution/util/nova/with_id/ML/predict";
            constexpr char* WithId_Train_DL_Path = "/api/solution/util/nova/with_id/DL/train";
            constexpr char* WithId_Predict_DL_Path = "/api/solution/util/nova/with_id/DL/predict";

            constexpr char* WithId_Status_Path = "/api/solution/util/nova/with_id/status";


            class VATEX_NOVA_AI
            {
                public:
                    VATEX_NOVA_AI(
                        std::string server_ip = "127.0.0.1", // same endpoint
                        unsigned int server_port = 10302,
                        std::string Id = "EDR-AI"
                    ): Requester(server_ip, server_port), Id(Id)
                    {}
                    ~VATEX_NOVA_AI() = default;

                    // 분류 전용 샘플 Push
                    template <typename T>
                    bool WithId_Sample_Push_Path_Classification(const std::string& sample_id, const std::vector<T>& sample, const std::string& sample_y)
                    {
                        try{

                            json sample_query = json::object();
                            if constexpr (
                                std::is_arithmetic_v<T>
                            )
                            {

                                sample_query = {
                                    {"id", Id},
                                    {"samples",  json::array({
                                        { {"sample_id", sample_id}, {"sample_x", sample}, {"sample_y", sample_y} } // Only One Sample
                                    }) }
                                };

                            }
                            else
                                return false;



                            auto result = Request_Post(WithId_Sample_Push_Path, sample_query);
                            return true;
                        }
                        catch (const std::exception& e) {
                            std:: cout << e.what();
                            return false;
                        }
                    }

                    // 회귀 전용 샘플 Push
                    template <typename T, typename Y>
                    bool WithId_Sample_Push_Path_Regression(const std::string& sample_id, const std::vector<T>& sample, const Y& sample_y)
                    {
                        try
                        {
                            json sample_query = json::object();
                            if constexpr (
                                std::is_arithmetic_v<T> && std::is_arithmetic_v<Y>
                            )
                            {

                                sample_query = {
                                    {"id", Id},
                                    {"samples",  json::array({
                                        { {"sample_id", sample_id}, {"sample_x", sample}, {"sample_y", sample_y} } // Only One Sample
                                    }) }
                                };

                            }
                            else
                                return false;



                            auto result = Request_Post(WithId_Sample_Push_Path, sample_query);
                            return true;
                        }
                        catch (const std::exception& e) {
                            std:: cout << e.what();
                            return false;
                        }
                    }

                    /////////////////////////////////////////////////////////////////////////

                    AI_Query::WithId::Status Get_WithId_Status()
                    {
                        try{
                            auto result = Request_Post(WithId_Status_Path, json::object({ {"id", Id} }));

                            auto Output = result["output"];

                            auto Status = AI_Query::WithId::Status{};
                            Status.samples_x_count = Output["samples_x_count"].get<unsigned long long>();

                            for( const auto& trained : Output["train_history"].get<std::vector<json>>() )
                            {
                                Status.train_history.push_back(
                                    AI_Query::WithId::status_history{
                                        
                                        .nano_timestamp = trained["nano_timestamp"].get<unsigned long long>(),
                                        .nano_timestamp_iso8901 = trained["nano_timestamp_iso8901"].get<std::string>(),

                                        .at_samples_x_count = trained["at_samples_x_count"].get<unsigned long long>(),

                                        .train_result = trained["train_result"].get<json>()
                                    }
                                );
                            }

                            return Status;
                        }
                        catch (const std::exception& e) {
                            std:: cout << e.what();
                            throw std::runtime_error("Get_WithId_Status");
                        }
                    }

                    ////////////////////////////////////////////////////////////////////////
                   
                    bool WithId_Train_ML(const std::string& y_type, const json& Train_value)
                    {
                        try{
                            auto result = Request_Post(WithId_Train_ML_Path, json::object( { {"id", Id},{"y_type", y_type},{"train", Train_value} } ));
                            return true;
                        }
                         catch (const std::exception& e) {
                            std:: cout << e.what();
                            return false;
                        }
                    }


                    ////////////////////////////////////////////////////////////////////////
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
                    std::string Id;

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

                        if(!response || response->status != 200)
                            throw std::runtime_error( "VATEX_NOVA_AI returned not 200 status" );

                        try
                        {
                            auto ai_response = json::parse(response->body);
                            std::cout << "ai_response: " << ai_response.dump() << std::endl;
                            if(!ai_response.contains("status") || ai_response["status"].get<bool>() == false)
                                throw std::runtime_error(  "No 'status' key in ai_response OR Failed " );

                            return ai_response; 
                        }
                        catch(const std::exception& e)
                        {
                            std::cerr << e.what() << '\n';
                            throw std::runtime_error( e.what() );
                        }
                        
                        
                    }
            };
        }
    }
}

#endif