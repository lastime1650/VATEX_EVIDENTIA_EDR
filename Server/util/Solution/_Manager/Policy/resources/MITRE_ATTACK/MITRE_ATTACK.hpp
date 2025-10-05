#ifndef MITRE_ATTACK_HPP
#define MITRE_ATTACK_HPP

#include "../../../../../../../util/util.hpp"
#include "../_Parent/BaseResourcePolicyModule.hpp" // 부모 클래스 헤더
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <sstream>
#include <stack>
#include <algorithm> // for std::replace
#include <regex>
#include <filesystem>


namespace Solution
{
    namespace Policy
    {
        namespace Resource
        {
            namespace MITRE_ATTACK
            {
                // ... PRECEDENCE, Metadata 네임스페이스는 변경 없음 ...
                inline std::map<std::string, int> PRECEDENCE = {
                    {"not", 3},
                    {"and", 2},
                    {"or", 1}
                };
                
                namespace Metadata
                {
                    struct METADATA
                    {
                        std::string rule_id;
                        std::string rule_name;
                        std::string rule_description;
                        std::string severity;
                        struct
                        {
                            bool is_valid = false;
                            std::string tactic_id;
                            std::string technique_id;
                            std::vector<std::string> data_sources;
                        } mitre_attack;
                    };
                }

                class RuleMatcher {
                public:
                    // ... 생성자(RuleMatcher)는 변경 없음 ...
                    explicit RuleMatcher(const json& rule_or_detection) {
                        const json* detection_part;

                        if (rule_or_detection.contains("detection")) {
                            detection_part = &rule_or_detection["detection"];
                            if (!rule_or_detection.contains("id") || !rule_or_detection.contains("name") || !rule_or_detection.contains("description") || !rule_or_detection.contains("severity")) {
                                throw std::invalid_argument("Full rule must contain 'id', 'name', 'description', and 'severity' fields.");
                            }
                            meta.rule_id = rule_or_detection.value("id","unknown");
                            meta.rule_name = rule_or_detection.value("name", "unknown");
                            meta.severity = rule_or_detection.value("severity", "unknown");
                            meta.rule_description = rule_or_detection.value("description", "unknown");

                            if(rule_or_detection.contains("mitre_attack"))
                            {
                                meta.mitre_attack.tactic_id = rule_or_detection["mitre_attack"].value("tactic", "");
                                meta.mitre_attack.technique_id = rule_or_detection["mitre_attack"].value("technique", "");
                                meta.mitre_attack.data_sources = rule_or_detection["mitre_attack"].value("data_sources", std::vector<std::string>());
                                meta.mitre_attack.is_valid = true;
                            }
                        }
                        else {
                            detection_part = &rule_or_detection;
                        }
                        
                        if (!detection_part->contains("selections") || !detection_part->contains("condition")) {
                            throw std::invalid_argument("Detection part must contain 'selections' and 'condition' fields.");
                        }

                        selections_ = (*detection_part)["selections"];
                        condition_string_ = (*detection_part)["condition"];

                        ParseConditionString();
                    }

                    // ... Match(const json&, bool) 함수는 변경 없음 ...
                    bool Match(const json& event, bool is_string_forced_lower = false ) const {
                        std::map<std::string, bool> selection_results;
                        for (auto const& [key, val] : selections_.items()) {
                            selection_results[key] = EvaluateSelection(val, event, is_string_forced_lower);
                        }
                        return EvaluateRPN(selection_results);
                    }

                    json Get_Rule_Metadata()
                    {
                        json result = {
                            {"id", meta.rule_id},
                            {"name", meta.rule_name},
                            {"description", meta.rule_description},
                            {"severity", meta.severity},
                        };

                        // [버그 수정] ! 연산자를 제거하여, mitre_attack 정보가 유효할 때만 데이터를 추가하도록 수정
                        if (meta.mitre_attack.is_valid) {
                            result["tactics"] = meta.mitre_attack.tactic_id;
                            result["technique"] = meta.mitre_attack.technique_id;
                            result["data_sources"] = meta.mitre_attack.data_sources;
                        }

                        return result;
                    }

                private:
                    // ... EvaluateSelection 함수는 변경 없음 ...
                    bool EvaluateSelection(const json& selection, const json& event, bool is_string_forced_lower = false) const {
                        if (!selection.contains("event_type") || !selection.contains("conditions")) return false;
                        
                        const std::string& event_type = selection["event_type"];
                        if (!event["body"].contains(event_type))
                        {
                            if (!event.contains("post")) return false;
                            if (!event["post"].contains(event_type)) return false;
                        }
                        
                        for (const auto& condition : selection["conditions"]) {
                            if (CheckCondition(condition, event, is_string_forced_lower)) {
                                return true;
                            }
                        }
                        return false;
                    }
                    
                    bool CheckCondition(const json& condition, const json& event, bool is_string_forced_lower = false) const {
                        try {
                            std::string field_path = condition.value("field", "");
                            const std::string& op = condition.value("operator", "");
                            const json& rule_value = condition.at("value");

                            std::replace(field_path.begin(), field_path.end(), '.', '/');
                            const json& event_value = event.at(json::json_pointer("/" + field_path));

                            if (event_value.is_string() && rule_value.is_string()) {
                                std::string event_str = event_value.get<std::string>();
                                std::string rule_str = rule_value.get<std::string>();

                                if (is_string_forced_lower) {
                                    // [버그 수정] 이벤트 경로와 규칙 경로 둘 다 정규화하여 일관성 유지
                                    event_str = std::regex_replace(event_str, std::regex(R"(\\+)"), "/");
                                    rule_str = std::regex_replace(rule_str, std::regex(R"(\\+)"), "/");

                                    std::transform(event_str.begin(), event_str.end(), event_str.begin(), ::tolower);
                                    std::transform(rule_str.begin(), rule_str.end(), rule_str.begin(), ::tolower);
                                }

                                if (op == "equals") return event_str == rule_str;
                                if (op == "contains") return event_str.find(rule_str) != std::string::npos;
                                if (op == "startswith") return event_str.rfind(rule_str, 0) == 0;
                                if (op == "endswith") {
                                    if (event_str.length() >= rule_str.length()) {
                                        return (0 == event_str.compare(event_str.length() - rule_str.length(), rule_str.length(), rule_str));
                                    }
                                    return false;
                                }
                            } else if (event_value.is_number() && rule_value.is_number()) {
                                if (op == "equals") return event_value == rule_value;
                                if (op == "gt") return event_value > rule_value;
                                if (op == "gte") return event_value >= rule_value;
                                if (op == "lt") return event_value < rule_value;
                                if (op == "lte") return event_value <= rule_value;
                            }
                        } catch (const json::exception&) {
                            return false;
                        }
                        return false;
                    }

                    // ... ParseConditionString, EvaluateRPN, 멤버 변수들은 변경 없음 ...
                    void ParseConditionString() {
                        std::string processed_condition = " " + condition_string_ + " ";
                        processed_condition.reserve(condition_string_.length() * 2);
                        processed_condition = std::regex_replace(processed_condition, std::regex("\\("), " ( ");
                        processed_condition = std::regex_replace(processed_condition, std::regex("\\)"), " ) ");
                        std::stringstream ss(processed_condition);
                        std::string token;
                        std::stack<std::string> op_stack;
                        while (ss >> token) {
                            if (selections_.contains(token)) {
                                rpn_tokens_.push_back(token);
                            } else if (PRECEDENCE.count(token)) {
                                while (!op_stack.empty() && op_stack.top() != "(" && PRECEDENCE.at(op_stack.top()) >= PRECEDENCE.at(token)) {
                                    rpn_tokens_.push_back(op_stack.top());
                                    op_stack.pop();
                                }
                                op_stack.push(token);
                            } else if (token == "(") {
                                op_stack.push(token);
                            } else if (token == ")") {
                                while (!op_stack.empty() && op_stack.top() != "(") {
                                    rpn_tokens_.push_back(op_stack.top());
                                    op_stack.pop();
                                }
                                if (!op_stack.empty()) op_stack.pop();
                                else throw std::runtime_error("Mismatched parentheses in condition string.");
                            }
                        }
                        while (!op_stack.empty()) {
                            if(op_stack.top() == "(") throw std::runtime_error("Mismatched parentheses in condition string.");
                            rpn_tokens_.push_back(op_stack.top());
                            op_stack.pop();
                        }
                    }

                    bool EvaluateRPN(const std::map<std::string, bool>& selection_results) const {
                        std::stack<bool> eval_stack;
                        for (const auto& token : rpn_tokens_) {
                            if (selections_.contains(token)) {
                                eval_stack.push(selection_results.at(token));
                            } else if (PRECEDENCE.count(token)) {
                                if (token == "not") {
                                    if (eval_stack.empty()) throw std::runtime_error("Invalid condition syntax for 'not'.");
                                    bool val = eval_stack.top(); eval_stack.pop();
                                    eval_stack.push(!val);
                                } else {
                                    if (eval_stack.size() < 2) throw std::runtime_error("Invalid condition syntax for binary operator.");
                                    bool val2 = eval_stack.top(); eval_stack.pop();
                                    bool val1 = eval_stack.top(); eval_stack.pop();
                                    if (token == "and") eval_stack.push(val1 && val2);
                                    else if (token == "or") eval_stack.push(val1 || val2);
                                }
                            }
                        }
                        if (eval_stack.size() != 1) {
                            if (condition_string_.empty() && eval_stack.empty()) return false;
                            throw std::runtime_error("Invalid final condition expression.");
                        }
                        return eval_stack.top();
                    }

                    Metadata::METADATA meta;
                    json selections_;
                    std::string condition_string_;
                    std::vector<std::string> rpn_tokens_;
                };

                class MITRE_ATTACK_RULE_MANAGER : public BaseResourcePolicyModule<RuleMatcher>
                {
                    public:
                        MITRE_ATTACK_RULE_MANAGER( std::string rules_dir ): BaseResourcePolicyModule<RuleMatcher>("mitre_attack", rules_dir){}
                        ~MITRE_ATTACK_RULE_MANAGER() {};

                        // [수정] 부모의 가상 함수를 재정의함을 명시적으로 나타내기 위해 'override' 키워드 추가
                        bool Match(json& InoutEvent) override
                        {
                            std::vector<json> output_matched;

                            // [버그 수정] 루프 조건식을 '==' 에서 '!=' 로 수정하여 루프가 정상적으로 실행되도록 함
                            for(auto it = rules.begin(); it != rules.end(); ++it)
                            {
                                if( (it->second).Match(InoutEvent, true) )
                                    output_matched.push_back(
                                        it->second.Get_Rule_Metadata()
                                    );
                            }

                            if(output_matched.empty())
                                return false;

                            InoutEvent["post"]["mitre_attack"] = json::array();
                            for (auto& detected : output_matched)
                            {
                                InoutEvent["post"]["mitre_attack"].push_back(detected);
                            }

                            return true;
                        }
                };
            }
        }
    }
}

#endif