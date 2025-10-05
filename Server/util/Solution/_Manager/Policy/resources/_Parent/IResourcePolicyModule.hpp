#ifndef IResourcePolicyModule_HPP
#define IResourcePolicyModule_HPP

#include "../../../../../../../util/util.hpp" // json 등을 위해 필요

namespace Solution
{
    namespace Policy
    {
        namespace Resource
        {
            // 모든 리소스 정책 모듈이 상속받아야 할 공통 인터페이스
            class IResourcePolicyModule
            {
            public:
                // 가상 소멸자는 다형적 소멸을 위해 필수입니다.
                ~IResourcePolicyModule(){};

                // 외부에서 호출할 공통 기능들을 순수 가상 함수로 정의합니다.
                virtual bool Match(json& InoutEvent) = 0;
                virtual std::string Get_module_name() = 0;
                virtual json Get_PolicyResourceModule_Info() = 0;
                virtual bool LoadRules(bool is_overwrite = false) = 0;
                // 필요하다면 다른 공통 함수들도 추가할 수 있습니다.
                // virtual bool Add_Rule_by_Binary(std::vector<uint8_t> inputBinary) = 0;
            };
            //inline IResourcePolicyModule::~IResourcePolicyModule() {}
        }
    }
}

#endif