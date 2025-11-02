// 시나리오 형 EDR 정책 클래스
#ifndef POLICY_EDR_HPP
#define POLICY_EDR_HPP

#include "../_Parent/BasePolicy.hpp"

// Mitre Attack & AgentEvent 매치 연동 
#include "../resources/Associoation/Association.hpp"

namespace Solution
{
    namespace Policy
    {
        // 모든 솔루션의 정책 "부모" 클래스 ( 일반화 )
        class EDRPolicy : public BasePolicy
        {
            /*
                EDR 정책은? 어떻게 구성되는가

                Resource_Policy_Module
                [
                    1. 연관분석
                ]

            */
            public:
                EDRPolicy( std::string RuleDir) 
                : 
                BasePolicy("EDR-Policy"), 
                Manager(RuleDir)
                { 
                    // 초기시에 디렉터리에 있는 json룰 로드한다.
                    std::cout << "EDR-Policy Reloading" << std::endl;
                    this->Manager.Reload_Rule();
                    std::cout << "EDR-Policy Reloaded" << std::endl;

                    // test
                    json s = {
                            {"body",
                                {
                                    {"process", {
                                        {"exe_path", "screencapture"}
                                    }}
                                }
                            }
                        };
                    this->Manager.Match(
                        s
                    );

                    BasePolicy::Set_Policy_Enable(); 
                }

                ~EDRPolicy(){};
                
                // ASSOCIATION_RULE_MANAGER 복사본 반환
                // Why? return that? 독립적인 연관분석을 위한 Context이기 때문임. (이미 생성자는 EDRPolicy에서 초기화했음)
                // 만약 Rule를 업데이트하기 위해선, EDRPolicy.Reload_AssociationRule() 호출 권장 나머지에서 호출하는 것은 복사본에서 한정됨
                std::shared_ptr<Solution::Policy::Resource::Association::ASSOCIATION_RULE_MANAGER> Get_Cloned_AssociationRuleCTX() const {
                    return Manager.Clone();
                }
                bool Reload_AssociationRule() {
                    return Manager.Reload_Rule();
                }

                /*
                    Override
                */
                // 정책 정보 반환
                json Get_Policy_Info() override {return _Get_Policy_Info();}

            private:
                

                // 1. ASSOCIATION_RULE_MANAGER
                Solution::Policy::Resource::Association::ASSOCIATION_RULE_MANAGER Manager;



                json _Get_Policy_Info()
                {
                    json res{
                        {"name", BasePolicy::PolicyName},
                        {"is_enable", BasePolicy::Get_is_enable()}
                    };

                    // 모듈 정보 반환 ( array )
                    res["modules"] = json::array();

                    // + 연동 정책 모듈
                    res["modules"].push_back( Manager.Get_PolicyResourceModule_Info() );

                    return res;
                }
        };
    }
}


#endif