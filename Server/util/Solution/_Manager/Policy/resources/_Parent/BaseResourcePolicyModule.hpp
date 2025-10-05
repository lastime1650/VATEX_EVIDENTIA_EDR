    #ifndef BaseResourcePolicyModule_HPP
    #define BaseResourcePolicyModule_HPP

    #include "../../../../../../../util/util.hpp"
    #include "IResourcePolicyModule.hpp" // [수정] 비-템플릿 인터페이스 헤더 포함

    namespace Solution
    {
        namespace Policy
        {
            namespace Resource
            {
                // 정책에서 활용하는 상세 모듈 - 부모 클래스
                // [수정] IResourcePolicyModule 인터페이스를 상속받아 다형성을 지원합니다.
                template<typename RuleClass>
                class BaseResourcePolicyModule : public IResourcePolicyModule
                {
                public:
                    
                    
                    std::string module_name;         // 모듈 명

                    // 정보 반환
                    // [수정] 부모 인터페이스의 가상 함수를 재정의함을 명시합니다.
                    json Get_PolicyResourceModule_Info() override
                    {
                        return
                        {
                            {"is_enable", Get_is_enable()},          // 활성여부
                            {"rule_dir_path", Get_is_rule_saved_dir_path()},        // 규칙 디스크 디렉터리 경로
                            {"rule_loaded_count", rules.size()} // 현재 로드된 규칙 개수
                        };
                    }

                protected:
                    BaseResourcePolicyModule( std::string module_name, std::string rule_saved_dir_path ) : module_name(module_name), rule_saved_dir_path(rule_saved_dir_path) {}
                    virtual ~BaseResourcePolicyModule() = 0;

                    /*
                        Virtual (from Interface)
                    */
                    // [수정] override 키워드를 추가하여 순수 가상 함수를 재정의함을 명시합니다.
                    // 자식 클래스가 반드시 이 함수를 구현해야 합니다.
                    virtual bool Match(json& InoutEvent) override = 0;

                    /*
                        Default (from Interface)
                    */
                    // [수정] override 키워드를 추가합니다.
                    std::string Get_module_name() override { return module_name; }

                    // [수정] override 키워드를 추가합니다.
                    // Disk 에 있는 JSON 규칙 파일을 읽어서 [rules] 에 저장
                    bool LoadRules(bool is_overwrite = false) override
                    {
                        // is_overwrite가 true일 경우, 기존 규칙을 모두 지우고 다시 로드합니다.
                        if (is_overwrite) {
                            rules.clear();
                        }
                        
                        bool status = _rule_reload();
                        if(!Get_is_enable() && status)
                            Set_Policy_Enable();
                            
                        return status;
                    }

                    /*
                        Default (Internal Implementation)
                    */
                    // 정책 리소스 모듈 룰 저장 경로 가져오기/편집
                    std::string Get_is_rule_saved_dir_path(){ return rule_saved_dir_path; }
                    void Set_rule_saved_dir_path(std::string to_change_rule_dir_path){ rule_saved_dir_path = to_change_rule_dir_path; }

                    // 정책리소스모듈 활성여부
                    bool Get_is_enable(){ return is_enable; }
                    void Set_Policy_Enable(){ is_enable = true; }
                    void Set_Policy_disable(){ is_enable = false; }

                    // [rule_saved_dir_path] 를 시작으로 해당 디렉터리 내 존재하는 모든 rule(json규격) 절대경로 string을 벡터로 반환
                    bool _get_rule_file_paths(std::vector<std::filesystem::path>& output)
                    {
                        std::string recent_rule_dir_path = Get_is_rule_saved_dir_path();
                        
                        try {
                            if (std::filesystem::exists(recent_rule_dir_path) && std::filesystem::is_directory(recent_rule_dir_path)) {
                                for (const auto& entry : std::filesystem::directory_iterator(recent_rule_dir_path)) {
                                    if (std::filesystem::is_regular_file(entry.path())) {
                                        output.push_back( std::filesystem::absolute(entry.path()) ); // 절대경로
                                    }
                                }
                                // 파일이 하나도 없는 경우도 유효한 상태이므로 false를 반환하지 않습니다.
                                return true;
                            } else {
                                //std::cerr << "디렉터리가 존재하지 않거나 올바르지 않습니다: " << recent_rule_dir_path << std::endl;
                                return false;
                            }
                        } catch (const std::filesystem::filesystem_error& e) {
                            //std::cerr << "파일 시스템 오류: " << e.what() << std::endl;
                            return false;
                        }
                    }

                    // rule_json 로드 -> std::vector에 저장
                    bool _rule_reload()
                    {
                        if(Get_is_rule_saved_dir_path().empty())
                            return false;
                        
                        std::vector<std::filesystem::path> rule_abs_paths;
                        if(!_get_rule_file_paths(rule_abs_paths))
                            return false;
                        
                        // 규칙을 디스크로부터 읽고 json으로 변환하여 등록
                        for(const auto& path : rule_abs_paths)
                        {
                            auto JSON_BIN = FileHandle.readFromFile(path.string());
                            if(JSON_BIN.empty())
                                continue;

                            try{
                                json RULE = json::parse( std::string( JSON_BIN.begin(), JSON_BIN.end() ) );
                                if(!RULE.contains("id"))
                                    throw std::runtime_error("RULE hasn't id key in file: " + path.string());

                                // json::value()를 사용하여 안전하게 id를 문자열로 가져옵니다.
                                std::string rule_id = RULE.value("id", "");
                                if (rule_id.empty()) {
                                    throw std::runtime_error("RULE has an empty id in file: " + path.string());
                                }

                                //rules[rule_id] = RuleClass(RULE);s
                                rules.emplace(rule_id, RuleClass(RULE));

                            } catch (const std::exception& e)
                            {
                                std::cerr << "Rule parsing error: " << e.what() << std::endl;
                                continue;
                            }
                        }
                        return true;
                    }
                    
                    // JSON파일을 저장
                    bool Add_Rule_by_Binary( std::vector<uint8_t> inputBinary )
                    {
                        try{
                            // [버그 수정] JSON_BIN -> inputBinary
                            json RULE = json::parse( std::string( inputBinary.begin(), inputBinary.end() ) );
                            if(!RULE.contains("id"))
                                throw std::runtime_error("RULE hasn't id key");

                            std::string rule_id = RULE.value("id", "");
                            if(rule_id.empty())
                                throw std::runtime_error("RULE has an empty id");

                            // 1. 메모리에 규칙 추가 또는 갱신
                            //rules[rule_id] = RuleClass(RULE);
                            rules.emplace(rule_id, RuleClass(RULE));

                            // 2. 규칙을 Disk에 저장
                            FileHandle.writeToFile( rule_saved_dir_path + "/" + rule_id + ".json", inputBinary);

                        } catch (const std::exception& e)
                        {
                            std::cerr << e.what() << std::endl;
                            return false;
                        }
                        return true;
                    }

                    // 규칙 확인
                    bool Is_there_rule(std::string rule_id)
                    {
                        return rules.find(rule_id) != rules.end();
                    }

                    /*
                        Field
                    */
                    bool is_enable = false;          // 활성여부
                    std::string rule_saved_dir_path; // 룰 저장 디렉터리
                    EDR::Util::File::FileHandler FileHandle; // 파일 핸들 클래스
                    std::map<std::string, RuleClass> rules;
                };
            }
        }
    }

    #endif