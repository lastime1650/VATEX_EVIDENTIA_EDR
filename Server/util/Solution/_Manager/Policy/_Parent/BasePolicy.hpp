#ifndef POLICY_BASE_HPP
#define POLICY_BASE_HPP

#include "../../../../../../util/util.hpp"

namespace Solution
{
    namespace Policy
    {
        // 모든 솔루션의 정책 "부모" 클래스 ( 일반화 )
        class BasePolicy
        {
            public:
                std::string PolicyName; // 정책 명
            protected:
                BasePolicy(std::string PolicyName) : PolicyName(PolicyName) {}
                virtual ~BasePolicy() = 0;

                // 정책 정보 반환 기능
                virtual json Get_Policy_Info() = 0;

                // 정책 활성여부
                bool Get_is_enable(){ return is_enable; }
                void Set_Policy_Enable(){ is_enable = true; }
                void Set_Policy_disable(){ is_enable = false; }

                
                bool is_enable = false; // 정책 활성 여부
        };
        inline BasePolicy::~BasePolicy() {}
    }
}


#endif