// 규칙기반 상관분석
#ifndef SCENARIO_HPP
#define SCENARIO_HPP
#include "../../../../../../../util/util.hpp"
#include "../_Parent/BaseResourcePolicyModule.hpp"

#include "../MITRE_ATTACK/MITRE_ATTACK.hpp" // 해당 규칙을 활용하기 위함

namespace Solution
{
    namespace Policy
    {
        namespace Resource
        {
            namespace SCENARIO
            {   
                using namespace MITRE_ATTACK; // 기존 RuleMatcher를 사용하기 위함

                class ScenarioRuleMatcher {
                public:
                    explicit ScenarioRuleMatcher(const json& rule) {
                        meta.rule_id = rule.value("id", "unknown_scenario");
                        meta.rule_name = rule.value("name", "Unknown Scenario");
                        meta.rule_description = rule.value("description", "");
                        meta.severity = rule.value("severity", "informational");

                        if (!rule.contains("detection") || !rule["detection"].is_array()) {
                            throw std::invalid_argument("Scenario rule must contain a 'detection' array.");
                        }

                        for (const auto& stage_item : rule["detection"]) {
                            if (!stage_item.is_object() || stage_item.empty()) continue;

                            auto const& [stage_name, stage_def] = stage_item.items().begin();

                            Stage current_stage;
                            current_stage.matcher = std::make_unique<RuleMatcher>(stage_def);

                            // [수정] 필드명을 'time_window_ns'로 통일하고, 조건 없이 파싱
                            // 첫 stage는 이 필드가 없으므로 기본값 0ULL이 사용됨
                            current_stage.time_window_ns = stage_def.value("time_window_ns", 0ULL);

                            stages_.push_back(std::move(current_stage));
                        }

                        if (stages_.empty()) {
                            throw std::invalid_argument("Scenario rule 'detection' array cannot be empty.");
                        }
                    }

                    bool Match(const json& event, bool is_string_forced_lower = false) {
                        if (IsComplete()) {
                            return false;
                        }

                        const auto& current_stage = stages_[current_stage_index_];

                        if (!current_stage.matcher->Match(event, is_string_forced_lower)) {
                            return false;
                        }

                        unsigned long long event_timestamp_ns;
                        try {
                            event_timestamp_ns = event.at(json::json_pointer("/header/nano_timestamp")).get<unsigned long long>();
                        }
                        catch (const json::exception&) {
                            return false;
                        }

                        if (current_stage_index_ == 0) {
                            last_match_timestamp_ns_ = event_timestamp_ns;
                        }
                        else {
                            if (current_stage.time_window_ns > 0 && // 시간 제약이 있을 때만 검사
                                event_timestamp_ns > last_match_timestamp_ns_ + current_stage.time_window_ns) {
                                // 시간 초과 시 시나리오 리셋 (정책에 따라 변경 가능)
                                // 여기서는 첫 stage부터 다시 시작하도록 리셋합니다.
                                // 만약 첫 stage가 현재 이벤트와도 맞다면, 바로 stage1이 성공한 상태가 됩니다.
                                Reset();
                                // 리셋 후 현재 이벤트로 다시 Match 시도
                                return Match(event, is_string_forced_lower);
                            }
                            last_match_timestamp_ns_ = event_timestamp_ns;
                        }

                        current_stage_index_++;

                        if (IsComplete()) {
                            return true;
                        }

                        return false;
                    }

                    void Reset() {
                        current_stage_index_ = 0;
                        last_match_timestamp_ns_ = 0;
                    }

                    bool IsComplete() const {
                        return current_stage_index_ >= stages_.size();
                    }

                    // [추가] 메타데이터 반환 함수
                    json Get_Rule_Metadata()
                    {
                        json result = {
                            {"id", meta.rule_id},
                            {"name", meta.rule_name},
                            {"description", meta.rule_description},
                            {"severity", meta.severity}
                        };

                        return result;
                    }

                    // [추가] 현재 진행 상태 확인 함수
                    size_t GetCurrentStageIndex() const {
                        return current_stage_index_;
                    }

                private:
                    struct Stage {
                        std::unique_ptr<RuleMatcher> matcher;
                        unsigned long long time_window_ns = 0;
                    };

                    Metadata::METADATA meta;
                    std::vector<Stage> stages_;
                    size_t current_stage_index_ = 0;
                    unsigned long long last_match_timestamp_ns_ = 0;
                };

                class SCENARIO_RULE_MANAGER : public BaseResourcePolicyModule<ScenarioRuleMatcher>
                {
                public:
                    SCENARIO_RULE_MANAGER(std::string RulePathDir) : BaseResourcePolicyModule<ScenarioRuleMatcher>("scenario", RulePathDir){}
                    ~SCENARIO_RULE_MANAGER(){};

                    // override
                    bool Match(json& InoutEvent) override
                        {
                            /*
                                << Input >>
                                {
                                    "header": {},
                                    "body" : {},
                                    "post": { "mitre_attack": [ {...},{...},,, ] }
                                }
                            */
                            /*
                                << Output >>
                                {
                                    "header": {},
                                    "body" : {},
                                    "post": { 
                                        "mitre_attack": [ {...},{...},,, ],
                                        "scenario": [ {...}, {...},,,, ] -> 생성됨
                                        }
                                }
                            */
                            if ( !InoutEvent.contains("header") || !InoutEvent.contains("body") || !InoutEvent.contains("post") )
                            {
                                throw std::runtime_error("no keys ");
                                return false;
                            }
                                
                        
                            /*
                                Matching
                            */
                            
                            if( !InoutEvent["post"].contains("mitre_attack") )
                                return false;

                            std::vector<json> output_matched;
                            for( auto& mitre_attack_post_element : InoutEvent["post"]["mitre_attack"].get<std::vector<json>>() )
                            {
                                _match(
                                    InoutEvent["header"],
                                    InoutEvent["body"],
                                    InoutEvent["post"]["mitre_attack"],
                                    output_matched
                                );
                            }
                            if(output_matched.empty())
                                return false; // no matched
                                
                            /*
                                Output
                            */
                            InoutEvent["post"]["mitre_attack"] = json::array();
                            for (auto& detected : output_matched)
                            {
                                InoutEvent["post"]["scenario"].push_back(detected);
                            }
                            return true;
                        }

                    private:
                        void  _match(json& header, json& body, json& post_mitre_attack, std::vector<json>& output_result)
                        {
                            for(auto it = rules.begin(); it == rules.end(); ++it)
                            {

                                json event_ = {
                                    {"header", header},
                                    {"body", body},
                                    {"post", { "mitre_attack", post_mitre_attack } }
                                };

                                if( (it->second).Match(event_, true) )
                                {
                                    output_result.push_back(
                                        (it->second).Get_Rule_Metadata()
                                    );
                                }
                            }
                        }
                    
                };
                
            } 
        }
    }
}

#endif
/*
#  MITRE_ATTACK에서 적용한 방식에서 확장된 방식.

{
  "id": "Scenario-01-001",
  "name": "Computer Attacking",
  "description": "Scenario Description",
  "severity": "medium",
  "detection": [
    {
      "stage1": {
        "is_matched": false,
        "selections": {
          "action_is_create": {
            "event_type": "filesystem",
            "conditions": [
              { "field": "body.filesystem.action", "operator": "equals", "value": "create" }
            ]
          },
          "mitre_attack_tech_1": {
            "event_type": "mitre_attack",
            "conditions": [
              { "field": "post.mitre_attack.tech_id", "operator": "equals", "value": "T1059" }
            ]
          }
        },
        "condition": "action_is_create and mitre_attack_tech_1"
      }
    },
    {
      "stage2": {
        "is_matched": false,
        "selections": {
          "file_in_temp": {
            "event_type": "filesystem",
            "conditions": [
              { "field": "body.filesystem.filepath", "operator": "startswith", "value": "C:\\Windows\\Temp\\" }
            ]
          },
          "extension_is_exe": {
            "event_type": "filesystem",
            "conditions": [
              { "field": "body.filesystem.filepath", "operator": "endswith", "value": ".exe" }
            ]
          }
        },
        "condition": "file_in_temp and extension_is_exe"
      }
    },
    {
      "stage3": {
        "is_matched": false,
        "selections": {
          "registry_persistence": {
            "event_type": "registry",
            "conditions": [
              { "field": "body.registry.path", "operator": "contains", "value": "\\Run\\" }
            ]
          }
        },
        "condition": "registry_persistence"
      }
    }
  ]
}

*/