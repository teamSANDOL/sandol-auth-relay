# Sandol Auth Relay

**Sandol Auth Relay**는 Keycloak 기반 인증 플로우를 챗봇 환경에 맞게 중계하는 **FastAPI 애플리케이션**입니다.
사용자 브라우저는 Relay를 통해 Keycloak과 상호작용하고, Relay는 발급받은 **Access Token**과 **Offline Refresh Token**을 챗봇 서버에 전달한 뒤 사용자를 지정된 경로로 리다이렉트합니다.

이 리포지토리는 내부 서비스 연동을 위한 참고 구현이며, 다양한 OIDC Relay 시나리오에도 응용할 수 있도록 설계되어 있습니다.

---

## 목차

- [Sandol Auth Relay](#sandol-auth-relay)
  - [목차](#목차)
  - [아키텍처 개요](#아키텍처-개요)
  - [인증 플로우](#인증-플로우)
  - [프로젝트 구조](#프로젝트-구조)
  - [필수 준비 사항](#필수-준비-사항)
  - [환경 변수](#환경-변수)
  - [클라이언트 설정 (`app/config/clients.json`)](#클라이언트-설정-appconfigclientsjson)
  - [시크릿 주입 규칙](#시크릿-주입-규칙)
  - [로컬 실행](#로컬-실행)
  - [Docker 실행](#docker-실행)
  - [주요 API](#주요-api)
    - [`POST /issue_login_link`](#post-issue_login_link)
    - [`GET /login/{lit}`](#get-loginlit)
    - [`GET /oidc/callback`](#get-oidccallback)
  - [챗봇 서버 토큰 관리 가이드](#챗봇-서버-토큰-관리-가이드)
  - [토큰 서명 및 검증](#토큰-서명-및-검증)
  - [세션 스토리지](#세션-스토리지)
  - [개발 가이드](#개발-가이드)
  - [트러블슈팅](#트러블슈팅)
  - [라이선스](#라이선스)

---

## 아키텍처 개요

```
사용자 브라우저 ──┐
                 │    (1) 로그인 링크 발급
 Sandol Auth Relay ──┐
                     │    (2) Keycloak 인가 코드 획득
         Keycloak ───┤
                     │    (3) Offline Refresh Token 발급
 챗봇 서버 (Refresh Flow) ◀─┘
```

- Relay는 Authorization Code Flow를 **대리 수행**하여, Keycloak으로부터 Access Token과 Offline Refresh Token을 발급받습니다.
- Relay는 두 토큰을 챗봇 서버로 POST 전달합니다.
- 챗봇 서버는 Offline Token을 안전하게 저장하고, 이후 자체적으로 Access Token을 갱신합니다.
- 사용자는 Relay가 지정한 `redirect_after` 주소로 리다이렉트됩니다.

---

## 인증 플로우

1. **로그인 링크 요청 (`POST /issue_login_link`)**

   - 챗봇 서버가 사용자 ID, 콜백 URL, 클라이언트 키 등을 담아 Relay에 요청합니다.
   - Relay는 JWT 기반 LIT(Login Initiation Token)을 생성하고 로그인 URL을 반환합니다.

2. **사용자 로그인 (`GET /login/{lit}`)**

   - 사용자는 챗봇이 전달한 LIT 링크를 열어 Relay에 접근합니다.
   - Relay는 LIT을 검증하고, PKCE 파라미터(state/nonce/code_verifier)를 생성한 뒤 Keycloak 인가 엔드포인트로 리다이렉트합니다.

3. **Keycloak 콜백 (`GET /oidc/callback`)**

   - Keycloak이 Authorization Code와 state를 Relay로 콜백합니다.
   - Relay는 state 검증 후 `scope=openid offline_access`로 Authorization Code를 교환합니다.
   - Keycloak은 Access Token과 Offline Refresh Token을 모두 반환합니다.

4. **챗봇 서버 알림**

   - Relay는 아래와 같은 payload를 챗봇 서버 콜백 URL로 POST합니다.
   - 챗봇은 Offline Token을 안전하게 저장하고, 필요할 때마다 `/token`에 `grant_type=refresh_token` 요청을 보내 Access Token을 재발급받습니다.

   ```jsonc
   {
     "relay_access_token": "<access_token>",
     "offline_refresh_token": "<refresh_token>",
     "issuer": "https://auth.example.com/realms/example",
     "aud": "kakao-bot",
     "chatbot_user_id": "user-123",
     "client_key": "kakao-bot",
     "ts": 1700000000,
     "nonce": "<random>"
   }
   ```

5. **사용자 최종 리다이렉트**

   - Relay는 사용자의 브라우저를 `redirect_after` 경로(허용 목록 내)로 리다이렉트합니다.

---

## 프로젝트 구조

```
app/
├─ config/
│  ├─ config.py          # 전역 설정, 클라이언트 로더, 로그 설정
│  └─ clients.json       # 클라이언트별 Keycloak 설정
├─ routers/
│  └─ auth.py            # 인증 관련 FastAPI 라우터
├─ schemas/
│  └─ auth.py            # Pydantic 스키마 정의
├─ utils/
│  ├─ __init__.py        # PKCE, LIT, 클라이언트 유틸 함수
│  ├─ kc_client.py       # KeycloakOpenID 헬퍼
│  ├─ security.py        # HMAC 서명 및 타임스탬프 검증
│  └─ storage.py         # diskcache 기반 세션 스토리지
main.py                  # FastAPI 엔트리포인트
pyproject.toml           # uv/PEP 621 기반 의존성 관리
docker-compose.yml       # 로컬 테스트용
```

---

## 필수 준비 사항

- Python 3.11 이상
- [uv](https://github.com/astral-sh/uv)
- Keycloak Realm 및 클라이언트 설정

  - **Standard Flow Enabled**
  - **Redirect URI**에 Relay 콜백 등록
  - **Client Scopes**에 `offline_access` 추가
- 챗봇 서버 (토큰 저장 및 갱신 담당)

---

## 환경 변수

| 이름 | 설명 | 기본값 |
| ------------------------------ | --------------------------------- | ------------------------------- |
| `BASE_URL`                     | Relay의 외부 접근 URL                  | `https://relay.example.com`     |
| `JWT_SECRET`                   | LIT 서명용 HS256 키                   | `dev-secret-please-change`      |
| `RELAY_TO_CHATBOT_HMAC_SECRET` | 챗봇 서버로 전달 시 HMAC 서명용 시크릿          | `dev-hmac-secret-please-change` |
| `STATE_TTL_SECONDS`            | state/nonce/code_verifier TTL (초) | `600`                           |
| `DEBUG`                        | `true`일 경우 DEBUG 로그 출력            | `false`                         |
| `SESSION_CACHE_DIR`            | diskcache 저장 위치                   | `.cache/sessions`               |

---

## 클라이언트 설정 (`app/config/clients.json`)

```json
{
  "kakao-bot": {
    "server_url": "https://auth.example.com/",
    "realm": "example",
    "client_id": "kakao-bot",
    "redirect_uri": "{BASE_URL}/oidc/callback",
    "issuer": "https://auth.example.com/realms/example",
    "scope": "openid offline_access"
  }
}
```

---

## 시크릿 주입 규칙

- `clients.json`에 `client_secret`이 없으면 환경 변수에서 자동 주입합니다.

  1. `CLIENT_KEY`를 대문자로 변환 + `__SECRETS` 접미사 (예: `KAKAO_BOT__SECRETS`)
  2. 소문자 원형 + `__secrets` (예: `kakao-bot__secrets`)

---

## 로컬 실행

```bash
uv sync
uv run uvicorn main:app --reload --host 0.0.0.0 --port 5600
```

`.env` 파일을 사용할 경우 `dotenv`를 통해 자동 로드하도록 설정할 수 있습니다.

---

## Docker 실행

```bash
docker compose up --build
```

---

## 주요 API

### `POST /issue_login_link`

- 챗봇 서버가 Relay에 로그인 링크를 요청합니다.
- 응답에는 로그인용 LIT 링크가 포함됩니다.

### `GET /login/{lit}`

- Relay가 LIT을 검증하고 Keycloak 인가 URL로 리다이렉트합니다.

### `GET /oidc/callback`

- Keycloak에서 Authorization Code와 state를 전달받습니다.
- Relay는 Code를 교환하여 **Access Token + Offline Refresh Token**을 발급받고, 챗봇 서버에 POST합니다.
- 챗봇 서버는 Offline Token을 저장하고 Refresh Flow로 Access Token을 갱신합니다.

---

## 챗봇 서버 토큰 관리 가이드

1. **Relay로부터 Offline Token을 수신**

   ```json
   {
     "offline_refresh_token": "<refresh_token>"
   }
   ```

   → 안전하게 저장 (암호화 및 Vault/KMS 사용)

2. **Access Token 갱신**

   ```bash
   POST https://auth.example.com/realms/example/protocol/openid-connect/token
   grant_type=refresh_token
   client_id=kakao-bot
   client_secret=<secret>
   refresh_token=<offline_refresh_token>
   ```

3. **갱신 시 주의사항**

   - 응답에 새 `refresh_token`이 오면 반드시 교체 저장.
   - 401 응답 시 재로그인 필요.
   - Realm 설정의 Idle/Max Lifespan을 초과하면 만료됨.

4. **갱신 주기**

   - Access Token 만료 1분 전 혹은 401 응답 시 즉시 갱신.
   - 최소 20~25일 간격으로 한 번 이상 refresh 요청 수행 (Idle Timeout 초기화용).

---

## 토큰 서명 및 검증

- **LIT**: HS256(JWT_SECRET)
- **챗봇 콜백 서명**: canonical JSON 후 HMAC-SHA256(base64url)
- **Timestamp 검증**: `verify_timestamps`에서 허용 오차(`skew`) 체크

---

## 세션 스토리지

- `diskcache.FanoutCache` 기반 state/nonce/code_verifier 저장소
- TTL 자동 만료
- Uvicorn 다중 워커 환경에서도 안전하게 공유 가능

---

## 개발 가이드

1. **코드 스타일**

   - [Ruff](https://docs.astral.sh/ruff/) 사용
     `ruff format`, `ruff check`
2. **Docstring**

   - Google Style + 한국어 설명
3. **로깅**

   - 환경 변수 `DEBUG=true` 시 DEBUG 로그 출력
4. **새 클라이언트 추가**

   - `clients.json`에 등록 후 `offline_access` 스코프를 포함

---

## 트러블슈팅

| 증상                         | 원인 / 해결                                |
| -------------------------- | -------------------------------------- |
| `unknown_client_key`       | `clients.json`에 정의된 키인지 확인             |
| `invalid_or_expired_state` | TTL 만료 혹은 중복 state 사용                  |
| `callback_failed`          | 챗봇 서버 콜백 URL 및 HMAC 검증 확인              |
| `no_offline_refresh_token` | Keycloak 클라이언트의 `offline_access` 설정 누락 |
| `401 invalid_grant`        | offline 토큰 만료, 재로그인 필요                 |

---

## 라이선스

내부 서비스용 예제 코드이며 별도 라이선스 지정 없음.
외부 배포 시 적절한 라이선스를 추가하십시오.
