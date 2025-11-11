#ifndef AI_MANAGER_HPP

#include "../../../../../util/util.hpp"
#include "../../../AgentTCP/AgentTcp.hpp"


namespace Solution
{
    namespace AI
    {
        using SampleX_Variant = std::variant<
            std::vector<float>,
            std::vector<int>,
            std::vector<unsigned int>,
            std::vector<unsigned long long>,
            std::vector<double>,
            std::vector<long long>
        >;

        using Sampley_Variant = std::variant<
            float,
            int,
            unsigned int,
            unsigned long long,
            double,
            long long,
            std::string
        >;

        struct AI_MANAGER_QUEUE_TYPE
        {
            SampleX_Variant Sample_x; // std::vector<T>가 여기에 저장됨
            std::string Sample_id;
            std::optional<Sampley_Variant> Sample_y;
        };

        
        class AI_MANAGER
        {
            public:
                AI_MANAGER( 
                    std::string server_ip, // same endpoint
                    unsigned int server_port,
                    
                    EDR::Server::AgentTcpManagement::AgentTcp& AgentTCPManager,
                    EDR::Util::ToSiem::SiemClient& SiemClient
                ): AiClient(server_ip, server_port), SiemClient(SiemClient), AgentTCPManager(AgentTCPManager)
                {
                    Run();
                }


                ~AI_MANAGER(){Stop();}

                bool Run()
                {
                    if(is_running)
                        return false;

                    /*
                    ============================================================================================================================================
                    
                    */
                    is_running = true;
                    QueueBasedAILoopThread = std::thread(
                        [this]()
                        {
                            try
                            {
                                while(this->is_running)
                                {
                                    auto Sample = SampleDataQueue.get();
                                    std::cout << "Sample 받음" << std::endl;
                                    std::string& Sample_id = Sample.Sample_id;


                                    /*
                                        A. 유효한 y를 받았을 때, Train을 위한 sample X +y 형식으로  NOVA_AI에 Sample Push (진행)
                                    */
                                    if (Sample.Sample_y.has_value())
                                    {
                                        std::visit(
                                            [&](const auto& sample_x,  const auto& sample_y) // 람다: variant 안의 실제 타입(const std::vector<T>&)을 받음
                                            {
                                                // concrete_vector는 std::vector<float>, std::vector<int> 등이 됩니다.

                                                // A.1. y가 std::string 계열인가? -> Classification 진행
                                                if constexpr (std::is_same_v<std::decay_t<decltype(sample_y)>, std::string>)
                                                {
                                                    this->_push_sample_classification_to_server(Sample.Sample_id, sample_x, sample_y);
                                                }
                                                
                                            }, 
                                            Sample.Sample_x, // 이 variant에 visit를 적용
                                            Sample.Sample_y.value()
                                        );
                                    }

                                }
                            }
                            catch(const std::exception& e)
                            {
                                std::cerr << e.what() << '\n';
                                is_running = false;
                                return;
                            }
                            
                        }
                    );

                    return true;
                }

                bool Stop()
                {
                    if(!is_running)
                        return false;

                    is_running = false;
                    if( QueueBasedAILoopThread.joinable() )
                    {
                        SampleDataQueue.stop();
                        QueueBasedAILoopThread.join();
                    }

                    return true;
                }

                template<typename SAMPLE_X_VecData, typename SAMPLE_Y_TYPE>
                void PushData(const std::string& id, std::vector<SAMPLE_X_VecData>& x_data, SAMPLE_Y_TYPE& y_data)
                {
                    AI_MANAGER_QUEUE_TYPE item;
                    item.Sample_id = id;
                    item.Sample_y = y_data;
                    item.Sample_x = x_data;

                    SampleDataQueue.put(std::move(item));
                }

                template<typename SAMPLE_X_VecData, typename SAMPLE_Y_TYPE>
                void PushData_with_Move(const std::string& id, std::vector<SAMPLE_X_VecData>&& x_data, SAMPLE_Y_TYPE&& y_data)
                {
                    AI_MANAGER_QUEUE_TYPE item;
                    item.Sample_id = id;
                    item.Sample_y = std::move(y_data);
                    item.Sample_x = std::move(x_data);

                    SampleDataQueue.put(std::move(item));
                }


                // 자동화 훈련체크용
                // 훈련해도 되는가?
                bool is_Possible_Train(unsigned long long* opt_out_samples_x_count = nullptr)
                {
                    return _is_Possible_Train(opt_out_samples_x_count);
                }

                /* 머신러닝 요청 */
                // 1. 분류 - 랜덤포레스트
                bool ML_RandomForest_Classification_Training()
                {

                    return _ML_RandomForest_Classification_Training();
                }

                

            private:
                bool is_running = false;
                EDR::Util::Queue::Queue<AI_MANAGER_QUEUE_TYPE> SampleDataQueue;
                std::thread QueueBasedAILoopThread;
                EDR::Util::AI::VATEX_NOVA_AI AiClient;                         // NOVA_AI - APISERVER_CLASS

                EDR::Server::AgentTcpManagement::AgentTcp& AgentTCPManager;     // AgentTCP - TCP Session CLASS
                EDR::Util::ToSiem::SiemClient& SiemClient;                      // SAPIENTIA - APISERVER_CLASS

                unsigned long long TrainTriggerBatchSize = 1000; // 훈련 안 된 1000개씩 데이터 이상 시 훈련 진행.

                
                template<typename VecData_T>
                bool _push_sample_classification_to_server(const std::string& sample_id, const std::vector<VecData_T>& sample_x, const std::string& y )
                {
                    return AiClient.WithId_Sample_Push_Path_Classification(
                        sample_id,
                        sample_x,
                        y
                    );
                }

                template<typename VecData_T>
                bool _push_sample_regression_to_server(const std::string& sample_id, const std::vector<VecData_T>& sample_x, const Sampley_Variant& y )
                {
                    return AiClient.WithId_Sample_Push_Path_Classification(
                        sample_id,
                        sample_x,
                        y
                    );
                }

                bool _is_Possible_Train(unsigned long long* opt_out_samples_x_count = nullptr)
                {
                    auto response = AiClient.Get_WithId_Status();

                    if(opt_out_samples_x_count)
                        *opt_out_samples_x_count = response.samples_x_count;

                    // 1. 현재 적재된 총 x 샘플값 비교
                    if( response.samples_x_count < TrainTriggerBatchSize )
                        return false;
                    


                    // 2. 최근 진행했던 Train에 대한 최선정보를 가져왔었을 때의 샘플값 계산하여 배치크기 체크
                    if(response.train_history.empty())
                        return true; // 한번도 훈련되지 못했고, 아직 history가 없는 경우는 true
                    
                    

                    auto current_sample_x_count = response.samples_x_count;                                     // 훈련 시작 현재 x 샘플 수
                    auto current_trained_at_sample_x_count = response.train_history.back().at_samples_x_count; // 훈련 시작 당시 x 샘플 수
                    if( (current_sample_x_count - current_trained_at_sample_x_count) < TrainTriggerBatchSize )
                        return false;

                    return true;
                }

                bool _ML_RandomForest_Classification_Training()
                {
                    return AiClient.WithId_Train_ML(
                        "label",
                        json::object({
                            {"model", {
                                {"model_name", "RandomForestClassifier"},
                                {"model_params", {
                                    {"n_estimators", 100},
                                    {"random_state", 4}
                                }}
                            }},
                            {"trainset", {
                                {"test_size", 0.25}
                            }}
                        })
                    );
                }
        };

    }
}


#endif


