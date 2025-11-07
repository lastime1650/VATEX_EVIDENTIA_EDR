#ifndef ASSOCIATION_HPP
#define ASSOCIATION_HPP

#include "../../../../../../../util/util.hpp"
#include "../_Parent/BaseResourcePolicyModule.hpp" // 부모 클래스 헤더
// 필요한 헤더 파일 포함
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <regex>
#include <iostream>

namespace Solution
{
    namespace Policy
    {
        namespace Resource
        {
            namespace Association
            {
                namespace Global
                {
                    // MITRE ATT&CK 정보 구조체
                    struct MitreAttack
                    {
                        std::string tactic_id;
                        std::string technique_id;
                        std::string subtechnique_id;
                        std::vector<std::string> data_sources;
                    };

                    // Action 관련 enum 및 구조체
                    enum ActionType { notice, block };
                    struct Action
                    {
                        ActionType type;
                        std::string description;
                    };

                    // Condition 연산자 enum
                    enum Operator { equals, contains, endswith, startswith, regex };

                    // 개별 조건 구조체
                    struct Condition
                    {
                        std::string field;
                        Operator op;
                        std::string value;
                        std::regex value_regex; // regex 연산자를 위한 컴파일된 정규식
                    };

                    // Selection (규칙의 가장 작은 조건 단위) 구조체
                    struct Selection
                    {
                        std::string id;
                        std::string event_type;
                        std::string condition_method; // "and" or "or"
                        std::vector<Condition> conditions;
                        
                        // 상태 추적 필드
                        unsigned long long count = 0; // 이 selection이 몇 번 매칭되었는지 카운트
                    };

                    // Inclusion (비순차적 조건 그룹) 구조체
                    struct Inclusion
                    {
                        std::string id;
                        std::map<std::string, Selection> selections; // selections는 map으로 관리 (id -> Selection)
                        Action action;
                    };
                    
                    // Stage-based detection을 위한 구조체 (명세서에 따라 추가)
                    // 현재 구현에서는 inclusion에 집중
                    
                    // 전체 규칙을 담는 최상위 구조체
                    struct AssociationRuleStruct
                    {
                        struct Header
                        {
                            std::string rule_id;
                            std::string rule_name;
                            std::string rule_description;
                            std::string rule_severity;
                            std::vector<MitreAttack> mitre_attacks;
                            std::vector<std::string> platforms;
                            std::string operational_usage;
                            std::string false_positive;
                        } header;

                        struct Body
                        {
                            std::vector<Inclusion> inclusions;
                            // std::vector<Stage> stages; // stage 로직 추가 시 필요
                        } body;
                    };
                }

                // 문자열을 enum으로 변환하는 헬퍼 함수들
                inline Global::Operator StringToOperator(const std::string& op_str) {
                    if (op_str == "equals") return Global::Operator::equals;
                    if (op_str == "contains") return Global::Operator::contains;
                    if (op_str == "endswith") return Global::Operator::endswith;
                    if (op_str == "startswith") return Global::Operator::startswith;
                    if (op_str == "regex") return Global::Operator::regex;
                    throw std::runtime_error("Unknown operator: " + op_str);
                }

                inline Global::ActionType StringToActionType(const std::string& type_str) {
                    if (type_str == "notice") return Global::ActionType::notice;
                    if (type_str == "block") return Global::ActionType::block;
                    throw std::runtime_error("Unknown action type: " + type_str);
                }
                
                class AssociationRuleObject
                {
                private:
                    // JSON 경로("body.process.exe_path")를 따라 값을 찾는 헬퍼 함수
                    const json* get_json_value(const json& event, const std::string& field_path) const {
                        std::stringstream ss(field_path);
                        std::string segment;
                        const json* current = &event;

                        while(std::getline(ss, segment, '.')) {
                            if (current->is_object() && current->contains(segment)) {
                                current = &(*current)[segment];
                            } else {
                                return nullptr; // 경로가 존재하지 않음
                            }
                        }
                        return current;
                    }

                    // 실제 값 비교 로직
                    bool compare_values(const json* event_val_json, const Global::Condition& cond, bool to_lower) const {
                        if (!event_val_json || event_val_json->is_null()) {
                            return false;
                        }

                        // JSON 값을 문자열로 변환 (숫자, 불리언 등도 처리)
                        std::string event_val_str;
                        if (event_val_json->is_string()) {
                            event_val_str = event_val_json->get<std::string>();
                        } else if (event_val_json->is_number()) {
                            event_val_str = std::to_string(event_val_json->get<long long>());
                        } else if (event_val_json->is_boolean()) {
                            event_val_str = event_val_json->get<bool>() ? "true" : "false";
                        } else {
                            return false; // 지원하지 않는 타입
                        }

                        std::string rule_val_str = cond.value;

                        if (to_lower) {
                            std::transform(event_val_str.begin(), event_val_str.end(), event_val_str.begin(), ::tolower);
                            std::transform(rule_val_str.begin(), rule_val_str.end(), rule_val_str.begin(), ::tolower);
                        }

                        switch (cond.op) {
                            case Global::Operator::equals:
                                return event_val_str == rule_val_str;
                            case Global::Operator::contains:
                                return event_val_str.find(rule_val_str) != std::string::npos;
                            case Global::Operator::endswith:
                                if (event_val_str.length() >= rule_val_str.length()) {
                                    return (0 == event_val_str.compare(event_val_str.length() - rule_val_str.length(), rule_val_str.length(), rule_val_str));
                                }
                                return false;
                            case Global::Operator::startswith:
                                return event_val_str.rfind(rule_val_str, 0) == 0;
                            case Global::Operator::regex:
                                return std::regex_search(event_val_str, cond.value_regex);
                        }
                        return false;
                    }


                public:
                    json RuleJSON;
                    mutable Global::AssociationRuleStruct RuleStruct; // Match 함수에서 count를 수정해야 하므로 mutable

                    explicit AssociationRuleObject(json ruleJSON) : RuleJSON(ruleJSON)
                    {
                        try {
                            // Header 파싱
                            RuleStruct.header.rule_id = RuleJSON.at("id").get<std::string>();
                            RuleStruct.header.rule_name = RuleJSON.at("name").get<std::string>();
                            RuleStruct.header.rule_description = RuleJSON.at("description").get<std::string>();
                            RuleStruct.header.rule_severity = RuleJSON.at("severity").get<std::string>();
                
                            if( RuleJSON.contains("mitre_attack") )
                            for (const auto& ma : RuleJSON.at("mitre_attack")) {
                                Global::MitreAttack attack;
                                attack.tactic_id = ma.at("tactic").get<std::string>();
                                attack.technique_id = ma.at("technique_id").get<std::string>();
                                attack.subtechnique_id = ma.value("subtechnique_id", "");
                                if(ma.contains("data_sources")) {
                                    for(const auto& ds : ma.at("data_sources")) {
                                        attack.data_sources.push_back(ds.get<std::string>());
                                    }
                                }
                                RuleStruct.header.mitre_attacks.push_back(attack);
                            }
                            
                            for (const auto& p : RuleJSON.at("platform")) {
                                RuleStruct.header.platforms.push_back(p.get<std::string>());
                            }
                            
                            RuleStruct.header.operational_usage = RuleJSON.value("operational_usage", "");
                            RuleStruct.header.false_positive = RuleJSON.value("false_positive", "");

                            // Body (detection) 파싱
                            if (RuleJSON.contains("detection") && RuleJSON["detection"].contains("inclusion")) {
                                for (const auto& inc_json : RuleJSON["detection"]["inclusion"]) {
                                    Global::Inclusion inclusion;
                                    inclusion.id = inc_json.at("id").get<std::string>();

                                    for (auto const& [sel_id, sel_json] : inc_json.at("selections").items()) {
                                        Global::Selection selection;
                                        selection.id = sel_id;
                                        selection.event_type = sel_json.at("event_type").get<std::string>();
                                        selection.condition_method = sel_json.at("condition_method").get<std::string>();
                                        
                                        for (const auto& cond_json : sel_json.at("conditions")) {
                                            Global::Condition condition;
                                            condition.field = cond_json.at("field").get<std::string>();
                                            std::string op_str = cond_json.at("operator").get<std::string>();
                                            condition.op = StringToOperator(op_str);
                                            
                                            // value가 숫자나 불리언일 수 있으므로 문자열로 변환
                                            if (cond_json.at("value").is_string()) {
                                                condition.value = cond_json.at("value").get<std::string>();
                                            } else {
                                                condition.value = cond_json.at("value").dump();
                                                // dump()는 따옴표를 포함할 수 있으므로 제거
                                                if (condition.value.front() == '"') condition.value.erase(0, 1);
                                                if (condition.value.back() == '"') condition.value.pop_back();
                                            }

                                            if (condition.op == Global::Operator::regex) {
                                                condition.value_regex = std::regex(condition.value, std::regex_constants::icase); // 대소문자 무시
                                            }
                                            selection.conditions.push_back(condition);
                                        }
                                        inclusion.selections[sel_id] = selection;
                                    }
                                    
                                    const auto& action_json = inc_json.at("action");
                                    inclusion.action.type = StringToActionType(action_json.at("type").get<std::string>());
                                    inclusion.action.description = action_json.at("description").get<std::string>();

                                    RuleStruct.body.inclusions.push_back(inclusion);
                                }
                            }
                        } catch (const json::exception& e) {
                            throw std::runtime_error("Failed to parse rule JSON: " + std::string(e.what()));
                        }
                    }

                    bool Match(const json& event, std::vector<Global::Action>& action_output, bool is_string_forced_lower = true) const {
                        // event_type이 없으면 매칭 불가
                        if (!event.contains("body") || !event["body"].is_object()) return false;
                        
                        // 이벤트의 실제 타입을 확인 (예: body 객체 안에 첫 번째 키)
                        std::string event_type;
                        if(event["body"].begin() != event["body"].end()){
                            event_type = event["body"].begin().key();
                        } else {
                            return false;
                        }

                        bool final_action_triggered = false;

                        // 모든 inclusion 규칙을 순회
                        for (auto& inclusion : RuleStruct.body.inclusions) {
                            
                            // [추가] 현재 이벤트가 이 inclusion 내의 selection 중 하나라도 매칭되었는지 추적하는 플래그
                            bool current_event_matched_a_selection = false;

                            // inclusion 내의 모든 selection을 순회
                            for (auto& [sel_id, selection] : inclusion.selections) {
                                // 1. 이벤트 타입이 일치하는지 확인
                                if (selection.event_type != event_type) {
                                    continue;
                                }

                                // 2. 조건들을 평가
                                bool selection_match = false;
                                if (selection.condition_method == "or") {
                                    for (const auto& cond : selection.conditions) {
                                        const json* event_val = get_json_value(event, cond.field);
                                        if (compare_values(event_val, cond, is_string_forced_lower)) {
                                            selection_match = true;
                                            break; // or 조건이므로 하나만 맞아도 성공
                                        }
                                    }
                                } else { // "and"
                                    selection_match = true;
                                    for (const auto& cond : selection.conditions) {
                                        const json* event_val = get_json_value(event, cond.field);
                                        if (!compare_values(event_val, cond, is_string_forced_lower)) {
                                            selection_match = false;
                                            break; // and 조건이므로 하나만 틀려도 실패
                                        }
                                    }
                                }

                                // 3. selection이 매칭되면 count 증가 및 플래그 설정
                                if (selection_match) {
                                    selection.count++;
                                    current_event_matched_a_selection = true; // [추가] 현재 이벤트가 기여했음을 표시
                                }
                            }

                            // 4. [수정] "현재 이벤트가 기여했을 때만" inclusion의 모든 selection이 충족되었는지 확인
                            if (current_event_matched_a_selection) {
                                bool all_selections_met = true;
                                for (const auto& [sel_id, selection] : inclusion.selections) {
                                    if (selection.count == 0) {
                                        all_selections_met = false;
                                        break;
                                    }
                                }
                                
                                // 5. 모든 selection이 충족되면 action 트리거
                                if (all_selections_met) {
                                    std::cout << event.dump(4) << std::endl; // 가독성을 위해 dump(4) 사용
                                    std::cout << "  RULE MATCHED: " << RuleStruct.header.rule_name << std::endl;
                                    std::cout << "  Inclusion ID: " << inclusion.id << std::endl;
                                    std::cout << "  Action: " << inclusion.action.description << std::endl;
                                    
                                    action_output.push_back(inclusion.action); // 외부로 action 전달
                                    final_action_triggered = true;
                                    
                                    // [추가] 매우 중요: Action이 트리거되었으므로, 이 inclusion의 상태를 초기화하여 중복 탐지를 방지
                                    for (auto& [sel_id, sel_to_reset] : inclusion.selections) {
                                        sel_to_reset.count = 0;
                                    }
                                }
                            }
                        }
                        return final_action_triggered;
                    }
                };


                class ASSOCIATION_RULE_MANAGER : public BaseResourcePolicyModule<AssociationRuleObject>
                {
                    public:
                        ASSOCIATION_RULE_MANAGER( std::string rules_dir ): BaseResourcePolicyModule<AssociationRuleObject>("association", rules_dir){}
                        ~ASSOCIATION_RULE_MANAGER() {};

                        // ASSOCIATION_RULE_MANAGER 복사본 반환
                        // Why? return that? 독립적인 연관분석을 위한 Context이기 때문임. 
                        std::shared_ptr<ASSOCIATION_RULE_MANAGER> Clone() const {
                            return std::make_shared<ASSOCIATION_RULE_MANAGER>(*this); // 깊은 복제
                        }

                        // [수정] 부모의 가상 함수를 재정의함을 명시적으로 나타내기 위해 'override' 키워드 추가
                        bool Match(const json& AgentEvent)  override
                        {
                            

                            // [버그 수정] 루프 조건식을 '==' 에서 '!=' 로 수정하여 루프가 정상적으로 실행되도록 함
                            for(auto it = rules.begin(); it != rules.end(); ++it)
                            {
                                std::vector<Global::Action> action;
                                if( (it->second).Match(AgentEvent, action, true) ) // AssociationRuleMatcher.Match() Method call
                                {
                                    std::cout << "\n\n[RuleMatched]: " << AgentEvent.dump() << "\n\n" <<std::endl;
                                }
                            }

                            return true;
                        }

                        bool Reload_Rule()
                        {
                            rules.clear();
                            bool output = BaseResourcePolicyModule::LoadRules();
                            std::cout << "Reload_Rule . count: " << rules.size() << std::endl;

                            return output;
                        }
                };
            }
        }
    }
}

#endif // ASSOCIATION_HPP