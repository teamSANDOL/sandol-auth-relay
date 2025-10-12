# Sandol Auth Relay

Sandol Auth Relay는 Keycloak 기반 인증 플로우를 챗봇 환경에 맞게 중계하는 FastAPI 애플리케이션입니다.  
사용자 브라우저는 Relay를 통해 Keycloak과 상호작용하고, Relay는 발급받은 Access Token을 챗봇 서버에 전달한 뒤 사용자를 지정된 경로로 리다이렉트합니다. 이 리포지토리는 내부 서비스 연동을 위한 참고 구현이지만, 다양한 OIDC Relay 시나리오에도 응용할 수 있도록 구성되어 있습니다.

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
    - [1. 의존성 설치](#1-의존성-설치)
    - [2. 개발 서버 실행](#2-개발-서버-실행)
    - [3. 환경 변수 설정](#3-환경-변수-설정)
  - [Docker 실행](#docker-실행)
  - [주요 API](#주요-api)
    - [`POST /issue_login_link`](#post-issue_login_link)
    - [`GET /login/{lit}`](#get-loginlit)
    - [`GET /oidc/callback`](#get-oidccallback)
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
                     │    (3) Access Token 교환
 챗봇 서버 (Token Exchange) ◀─┘
```

- **Relay**는 Keycloak Authorization Code Flow를 대신 수행하고, Access Token을 챗봇 서버에 POST로 전달합니다.
- 챗봇 서버는 전달받은 Access Token을 사용해 Token Exchange를 수행하거나 사용자 인증을 완료합니다.
- 최종적으로 사용자는 전달된 `redirect_after` 주소로 리다이렉트됩니다.

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
   - Relay는 state 검증 후 PKCE를 포함해 Code를 Access Token으로 교환합니다.

4. **챗봇 서버 알림**
   - Relay는 Access Token, issuer, aud 등을 서명(signature)과 함께 챗봇 콜백 URL로 POST합니다.
   - 챗봇 서버는 Token Exchange 혹은 자체 검증을 수행합니다.

5. **사용자 최종 리다이렉트**
   - Relay는 사용자의 브라우저를 `redirect_after` 값(허용 목록 내)에 맞춰 리다이렉트합니다.

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
main.py                  # FastAPI 애플리케이션 엔트리포인트
pyproject.toml           # uv/PEP 621 기반 의존성 관리
docker-compose.yml       # 로컬 통합 테스트용 서비스 정의
```

---

## 필수 준비 사항

- Python 3.11.x
- [uv](https://github.com/astral-sh/uv) (의존성 설치 및 실행 권장)
- Keycloak 서버 및 클라이언트 등록
- 챗봇 서버(또는 Access Token을 처리할 백엔드)
- 환경 변수 설정 파일(.env) 혹은 런타임 환경 변수 구성

---

## 환경 변수

| 이름 | 설명 | 기본값 |
| ---- | ---- | ------ |
| `BASE_URL` | Relay가 외부에서 접근 가능한 베이스 URL | `https://relay.example.com` |
| `JWT_SECRET` | LIT 서명/검증용 HS256 시크릿 | `dev-secret-please-change` |
| `LIT_ISSUER` | LIT 토큰 발급자 | `auth-relay` |
| `LIT_AUDIENCE` | LIT 토큰 대상자 | `lit-consumer` |
| `STATE_TTL_SECONDS` | state/nonce/code_verifier 유효 시간(초) | `600` |
| `RELAY_TO_CHATBOT_HMAC_SECRET` | 챗봇 서버로 전달 시 서명 생성용 시크릿 | `dev-hmac-secret-please-change` |
| `DEBUG` | `true`일 때 콘솔 로그를 DEBUG 레벨로 출력 | `False` |
| `SESSION_CACHE_DIR` | diskcache 저장 디렉터리 | `<repo>/.cache/sessions` |

추가로, 클라이언트 시크릿을 환경 변수로 주입하려면 [시크릿 주입 규칙](#시크릿-주입-규칙)을 참고하세요.

---

## 클라이언트 설정 (`app/config/clients.json`)

클라이언트별 최소 필드만 JSON으로 정의합니다. `{BASE_URL}` 플레이스홀더는 런타임에 `BASE_URL` 값으로 치환됩니다.

```json
{
  "kakao-bot": {
    "server_url": "https://auth.example.com/",
    "realm": "example",
    "client_id": "kakao-bot",
    "redirect_uri": "{BASE_URL}/oidc/callback",
    "issuer": "https://auth.example.com/realms/example"
  }
}
```

지원 필드:

- `server_url` (필수\*): Keycloak 서버 URL (`.../auth/`)
- `realm` (필수\*): Keycloak Realm 이름
- `client_id` (필수)
- `redirect_uri` (필수): Keycloak에 등록된 Redirect URI
- `issuer` (필수): Well-known issuer URL
- `scope` (선택): OIDC Scope (`openid` 기본값)
- `client_secret` (비추천): 환경 변수를 통해 주입할 것을 권장합니다.

\* `server_url`, `realm`은 기본적으로 필수이지만 `issuer`가 제공되면 비어 있는 경우 자동으로 유추됩니다.

---

## 시크릿 주입 규칙

- 코드는 JSON에 `client_secret`이 없으면 아래 순서로 환경 변수를 탐색합니다.
  1. `CLIENT_KEY`를 대문자/영문자로 정규화한 뒤 `__SECRETS`를 붙인 키 (예: `KAKAO_BOT__SECRETS`)
  2. 원래 키를 그대로 사용해 `client_key__secrets` (예: `kakao-bot__secrets`)
- 발견된 첫 번째 값을 `client_secret`으로 설정하고, `DEBUG`가 켜진 경우 로그로 어떤 키에서 가져왔는지 알려줍니다.

---

## 로컬 실행

### 1. 의존성 설치

```bash
uv sync
```

### 2. 개발 서버 실행

```bash
uv run uvicorn main:app --reload --host 0.0.0.0 --port 5600
```

- FastAPI `root_path`가 `/relay`로 설정되어 있으므로 게이트웨이에서 `/relay` 경로로 마운트되는 것을 가정합니다.

### 3. 환경 변수 설정

`uv run` 명령 앞에 `BASE_URL` 등 필요한 값을 export하거나, `.env`를 사용하려면 `dotenv`를 설치해 직접 로드하세요.

---

## Docker 실행

`docker-compose.yml`을 참고하면 Keycloak/챗봇 Stub과의 통합 테스트를 구성할 수 있습니다.
예시:

```bash
docker compose up --build
```

필요에 따라 `SESSION_CACHE_DIR`을 볼륨으로 마운트해 다중 워커 간 일관성을 확보하세요.

---

## 주요 API

### `POST /issue_login_link`

- **Body**: `IssueLinkReq`

  ```jsonc
  {
    "chatbot_user_id": "user-123",
    "callback_url": "https://bot.example.com/callback",
    "client_key": "kakao-bot",
    "redirect_after": "https://app.example.com/home"
  }
  ```

- **Response**: `IssueLinkRes`

  ```jsonc
  {
    "login_link": "https://relay.example.com/relay/login/<LIT>",
    "expires_in": 600
  }
  ```

- **에러**
  - `400 redirect_after_not_allowed`: 허용되지 않은 리다이렉트.

### `GET /login/{lit}`

- LIT 토큰을 검증 후 Keycloak 인가 URL로 302 리다이렉트합니다.
- state/nonce/code_verifier를 diskcache에 저장합니다.
- 에러 시 `400 missing_required_claims` 등을 반환합니다.

### `GET /oidc/callback`

- Keycloak에서 전달한 Authorization Code를 Access Token으로 교환합니다.
- 챗봇 서버로 아래 payload를 POST합니다.

  ```jsonc
  {
    "relay_access_token": "<access_token>",
    "issuer": "https://auth.example.com/realms/example",
    "aud": "kakao-bot",
    "chatbot_user_id": "user-123",
    "client_key": "kakao-bot",
    "ts": 1700000000,
    "nonce": "<random>"
  }
  ```

- 헤더 `X-Relay-Signature`에는 `RELAY_TO_CHATBOT_HMAC_SECRET`로 생성한 서명이 포함됩니다.
- 챗봇 서버 응답이 실패하면 `502 {"error":"callback_failed"}`로 종료합니다.

---

## 토큰 서명 및 검증

- **LIT (Login Initiation Token)**: HS256으로 서명되며, Relay와 챗봇이 공유하는 `JWT_SECRET`을 사용합니다.
- **챗봇 콜백 서명**: `canonical_json` 후 HMAC-SHA256(base64url)로 생성합니다.
- **Timestamp 검증**: `verify_timestamps`에서 허용 오차(`skew`) 내에 있지 않으면 `timestamp_skew` 에러를 발생시킵니다.

---

## 세션 스토리지

- `diskcache.FanoutCache`를 사용해 state/nonce/code_verifier 등을 자동 만료(TTL)와 함께 저장합니다.
- 기본 디렉터리: `<repo>/.cache/sessions`
- 환경 변수 `SESSION_CACHE_DIR`로 커스터마이즈 가능합니다.
- 동시성:
  - FanoutCache는 멀티 프로세스/멀티 스레드에서 안전하게 동작합니다.
  - Uvicorn 다중 워커 실행 시 동일 디렉터리를 공유하면 일관성 유지가 가능합니다.

---

## 개발 가이드

1. **코드 스타일**
   - [Ruff](https://docs.astral.sh/ruff/)를 사용해 린트/포맷 (`ruff format`, `ruff check`)
   - Docstring은 Google Style을 사용하며 설명은 한국어로 작성합니다.

2. **테스트**
   - 현재 기본 테스트 스위트는 없습니다. FastAPI `TestClient` 혹은 httpx를 이용한 엔드투엔드 테스트 추가를 권장합니다.

3. **로깅**
   - 환경 변수 `DEBUG=true`로 설정하면 DEBUG 레벨 로그까지 출력합니다.
   - 기본 로거 이름: `sandol-auth-relay-service`

4. **새로운 클라이언트 추가**
   - `app/config/clients.json`에 엔트리를 추가하고 `client_secret`은 JSON 또는 환경 변수로 주입합니다.
   - Keycloak에 Redirect URI를 반드시 등록해야 합니다.

---

## 트러블슈팅

| 증상 | 해결 방법 |
| ---- | -------- |
| `unknown_client_key` | `clients.json`에 정의된 `client_key`인지 확인합니다. |
| `redirect_after_not_allowed` | `Config.REDIRECT_ALLOWLIST`에 도메인 또는 경로를 추가합니다. |
| `invalid_or_expired_state` | state TTL이 만료되었거나 중복 사용입니다. `STATE_TTL_SECONDS`를 조정하거나 브라우저에서 새로고침 시 새 링크를 요청하세요. |
| 챗봇 콜백 502 | 챗봇 서버 URL, HMAC 서명 검증 로직, 네트워크 접근성을 확인합니다. |
| `client_secret missing` 로그 | 환경 변수 또는 `clients.json`에 시크릿을 설정합니다. |

---

## 라이선스

내부 서비스용 샘플 코드로 별도 라이선스는 지정되어 있지 않습니다.  
외부 배포 시 적절한 라이선스를 추가해 주세요.
