# User API Server 과제

Spring Boot 기반 사용자/관리자 인증 및 메시지 발송 API 서버입니다.  
Java 17을 기반으로 하며, Windows 환경에서 실행할 수 있도록 구성되어 있습니다.

---

## 📁 프로젝트 구조

```
📦 userapi-server       # 메인 API 서버 (포트: 8080)
📦 kakao-server         # 카카오톡 메시지 Mock 서버 (포트: 8081)
📦 sms-server           # SMS 메시지 Mock 서버 (포트: 8082)
📄 run-mock.bat         # Mock 서버 실행 스크립트 (Windows용)
📄 run-userapi.bat      # 메인 서버(API 서버) 실행 스크립트 (Windows용)
```

---

## 🚀 실행 순서

1. **Java 17**이 설치되어 있어야 합니다.  
   다운로드: https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html

2. 프로젝트 루트 디렉토리에서 아래 순서대로 실행하세요.

### 1️⃣ Mock 서버 실행

`run-mock.bat` 실행 → `kakao-server`와 `sms-server`(8081/8082)가 각각 실행됩니다.

> ⚠️ 각 Mock 서버는 별도 콘솔 창에서 실행됩니다.  
> 종료 시 해당 콘솔 창을 직접 닫아주세요.

### 2️⃣ 메인 서버 실행 및 테스트

`run-userapi.bat` 실행 → 메인 API 서버(8080)가 구동되며 테스트가 자동 수행됩니다.  
테스트 결과는 브라우저에서 `index.html`로 확인 가능합니다.

---

## ✅ 사용 기술 스택

- Java 17
- Spring Boot 3.x
- Spring Security (세션 기반 인증 / Basic Auth)
- JPA + H2 Database (인메모리)
- Bucket4j (API Rate Limit)
- Gradle

---

## 🛠️ 주요 기능

- 사용자 회원가입 및 로그인
- 로그인한 사용자 본인 정보 조회
- 관리자 전용 사용자 목록 조회 (페이징)
- 관리자 전용 사용자 정보 수정 / 삭제
- 관리자 → 전체 사용자 대상 메시지 전송
  - 카카오톡 메시지 우선 발송
  - 실패 시 SMS로 자동 대체 발송
  - 카카오톡: 분당 100건 제한 / SMS: 분당 500건 제한

---

## 📬 외부 메시지 API 명세

| 구분 | URL | 인증 방식 | 기타 |
|------|-----|------------|------|
| 카카오톡 | `POST http://localhost:8081/kakaotalk-messages` | Basic Auth (`autoever` / `1234`) | JSON |
| SMS     | `POST http://localhost:8082/sms?phone=...`     | Basic Auth (`autoever` / `5678`) | x-www-form-urlencoded |

※ 모든 메시지 API 호출은 실패 시 자동 fallback 로직(SMS)이 적용됩니다.

---

## 🧪 테스트 가이드

- 전체 테스트는 `run-userapi.bat` 실행 시 자동 수행됩니다.
- 별도로 테스트만 실행하고 싶을 경우:
  ```bash
  ./gradlew clean test
  ```