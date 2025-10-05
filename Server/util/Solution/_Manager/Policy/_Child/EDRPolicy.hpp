// 시나리오 형 EDR 정책 클래스
#ifndef POLICY_SCENARIO_HPP
#define POLICY_SCENARIO_HPP

#include "../_Parent/BasePolicy.hpp"

// Mitre Attack & AgentEvent 매치 연동 
#include "../resources/MITRE_ATTACK/MITRE_ATTACK.hpp"
#include "../resources/Scenario/Scenario.hpp"

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
                    1. MITRE ATTACK 연동 정책 모듈                      >> ( 단일 이벤트에 대한 마이터 어택 기술ID 매핑)
                    2. 이벤트 연관분석 정책 모듈 ( depends (1) )         >> ( 프로세스 트리 연관 분석 )
                ]

            */
            public:
                EDRPolicy( std::string MitreAttackRuleDir, std::string ScenarioRuleDir  ) 
                : 
                BasePolicy("EDR-Policy"), 
                MITRE_ATTACK_Rule_Manager(MitreAttackRuleDir),
                SCENARIO_Rule_Manager(ScenarioRuleDir)
                { 
                    BasePolicy::Set_Policy_Enable(); 
                }

                ~EDRPolicy(){};

                /*
                    이벤트 단위 규칙 적용
                    -> 1회성 처리
                */
                // 마이터 어택 규칙 TechID연동
                bool Event_Mitre_Attack_mapping(json& Inout_event)
                {
                    if(!Inout_event.contains("header") || !Inout_event.contains("body") )
                        throw std::runtime_error("no keys'header' or 'body' in Agent Event ");
                    // post 체크후 없으면 생성 ( 대부분 있어야함 )
                    if(!Inout_event.contains("post"))
                        Inout_event["post"] = json::object();
                    /*
                        [Before]
                        {
                            "header": {},
                            "body": {},
                            "post": {...} <- post 에 mitre_attack key 생성 (만약, post가 없다면 생성한다)
                        }
                    */
                   /*
                        [After]
                        {
                            "header": {},
                            "body": {},
                            "post": { 
                                "mitre_attack" : [ {...}, {...} ,,, ]<- 생성 (단, 결과가 없으면 해당 키는 무효하다)
                            } 
                        }
                   */
                    
                    if( 
                        !MITRE_ATTACK_Rule_Manager.Match(
                            Inout_event                // Inout
                        )
                    )
                        return false;
                    
                    
                    

                    return true;

                }

                /*
                    ** 이벤트 단위 규칙을 사전에 실시해야 탐지력이 배로 올라간다.

                    시나리오 형 연관 분석 규칙 적용
                    -> 연속성 ( vector이벤트 처리하므로 ) 처리 (저장된 시나리오 규칙을 복사해서 Stage 도장깨기형 처리)
                */
                // 마이터 어택 규칙 확장형 활용
                // 이벤트를 타임라인 순으로 매긴후 해당 이벤트를 타임스탬프 (Old->new) 순으로 정렬하여 연관분석 규칙과 매칭하는 것. 
                bool Event_association_mapping_by_MitreAttack(json& InputEvent)
                {
                    /*
                        "post" 키가 필요함
                    */
                   /*
                        [Before]
                        {
                            "header": {},
                            "body": {},
                            "post": { 
                                "mitre_attack" : [ {...}, {...} ,,, ]<- 리스트 형태로 json요소(마이터어택 기술ID) 매핑 값이 있으며, 분석시에는 for문으로 돌려가면서 규칙 처리
                            } 
                        }
                   */
                  /*
                        [After]
                        {
                            "header": {},
                            "body" : {},
                            "post": { 
                                "mitre_attack": [ {...},{...},,, ],
                                "scenario": [ {...}, {...},,,, ] -> 연관분석
                            }
                        }
                    }
                  */
                    return SCENARIO_Rule_Manager.Match( InputEvent );
                }

                /*
                    Override
                */
                // 정책 정보 반환
                json Get_Policy_Info() override {return _Get_Policy_Info();}

            private:
                

                // 1. MITRE ATTACK 연동 정책 모듈
                Solution::Policy::Resource::MITRE_ATTACK::MITRE_ATTACK_RULE_MANAGER MITRE_ATTACK_Rule_Manager;
                // 2. 연관 분석 정책
                Solution::Policy::Resource::SCENARIO::SCENARIO_RULE_MANAGER SCENARIO_Rule_Manager;



                json _Get_Policy_Info()
                {
                    json res{
                        {"name", BasePolicy::PolicyName},
                        {"is_enable", BasePolicy::Get_is_enable()}
                    };

                    // 모듈 정보 반환 ( array )
                    res["modules"] = json::array();

                    // + 연동 정책 모듈
                    res["modules"].push_back( MITRE_ATTACK_Rule_Manager.Get_PolicyResourceModule_Info() );
                    res["modules"].push_back( SCENARIO_Rule_Manager.Get_PolicyResourceModule_Info() );

                    return res;
                }
        };
    }
}


#endif