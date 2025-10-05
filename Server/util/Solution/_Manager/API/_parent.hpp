#ifndef API_PARENT_HPP
#define API_PARENT_HPP

/*
    보안솔루션의 API 서버를 정의하기 위한 
    - 추상 클래스

    모든 유형의 메서드를 모두 선언하며, 가상 메서드시 구현이 필요하지 않은 경우는 자식에서 false반환한다. 
*/
#include <string>
#include <iostream>
#include <map>


namespace Solution
{
    namespace API
    {

        namespace Parameters
        {
            namespace Request
            {
                // parent sturct
                struct BaseRequest
                {
                    std::map<std::string , std::string> args;
                };

                // child
                struct QueryRequest : public BaseRequest
                {

                };
                struct PolicyRequest : public BaseRequest
                {
                    std::string PolicyId;
                };
                struct ActionRequest  : public BaseRequest
                {
                    std::string Target;
                };
            }
            

            struct API_Result
            {
                bool is_success = false;
                std::string message;
            };
        }

        class SolutionAPI
        {
        protected:
            SolutionAPI() = default;
            virtual ~SolutionAPI() = default;

            /*
                Solution ( 솔루션 정보 조회 )

                ** 반환 값은 솔루션마다 다름 
            */
            virtual Parameters::API_Result Solution_Query_Server_Info( Parameters::Request::QueryRequest request ) = 0; // 솔루션 서버 [기본 정보]
            virtual Parameters::API_Result Solution_Query_Server_Status( Parameters::Request::QueryRequest request ) = 0; // 솔루션 서버 [현재 상태] 
            /*
                Policy ( 정책 조회 및 추가 또는 삭제 )
            */
            virtual Parameters::API_Result Policy_Query( Parameters::Request::PolicyRequest request ) = 0;
            virtual Parameters::API_Result Policy_Add( Parameters::Request::PolicyRequest request ) = 0;
            virtual Parameters::API_Result Policy_Remove( Parameters::Request::PolicyRequest request ) = 0;
            /*
                [Action] -> Response ( 즉각 차단 )
            */
            virtual Parameters::API_Result Action_Response( Parameters::Request::ActionRequest request ) = 0; // 차단 요청
            virtual Parameters::API_Result Action_UnResponse( Parameters::Request::ActionRequest request ) = 0; // 차단 해제 요청 ( 예시) 각 솔루션의 차단 목록에 있는 sqlite와 비교하여 즉각 차단 해제)
            

        };
    }
}


#endif

/*

🔹 1. EDR (Endpoint Detection & Response)
카테고리	쿼리 항목	설명
에이전트 상태	Agent 상태 확인	설치 여부, 버전, 작동 상태
보호 상태	Endpoint 보호 수준	실시간 감시, 정책 적용 여부
이벤트	최근 탐지 이벤트	탐지된 악성코드, 공격 유형, 타임스탬프
정책	적용 정책	EDR에 적용된 정책 정보, 시나리오 기반 정책 등
차단 상태	현재 차단된 대상	호스트, 프로세스 등

🔹 2. NDR (Network Detection & Response)
카테고리	쿼리 항목	설명
센서 상태	NDR 센서 상태	배치 위치, 패킷 수집 상태
트래픽 분석	비정상 트래픽	이벤트/알람 발생 내역
정책	네트워크 이상 탐지 정책	임계값, 자동 격리 설정 등
차단 상태	격리된 디바이스 목록	네트워크 차단 대상 확인
연결 정보	연결된 디바이스/세그먼트	현재 모니터링 중인 네트워크 구성

🔹 3. CloudDR (Cloud Detection & Response)
카테고리	쿼리 항목	설명
연결 현황	워크로드/VM 목록	현재 연결된 인스턴스, 클러스터
사용자/계정 현황	계정 리스트 및 권한	클라우드 계정, IAM 역할
정책	적용된 보안 정책	CloudDR에서 강제하는 규칙, 시큐리티 그룹 등
이벤트	탐지 이벤트	권한 남용, 취약점 공격, 로그 이상 등
차단 상태	격리된 워크로드/리소스	비정상 접근 차단 대상

🔹 4. MailDR (메일 보안 / 이메일 DR)
카테고리	쿼리 항목	설명
연결 현황	메일 서버 연결 상태	SMTP/IMAP/Exchange 계정 상태
정책	스팸/피싱 필터 정책	차단 수준, 알림 수준, 특정 도메인 허용/차단
이벤트	탐지 이벤트	스팸, 피싱, 악성 첨부 파일 탐지 내역
계정 현황	모니터링 대상 계정	보호 대상 메일 계정 리스트
차단 상태	차단된 메일/발신자	격리된 이메일, 발신자 목록

*/