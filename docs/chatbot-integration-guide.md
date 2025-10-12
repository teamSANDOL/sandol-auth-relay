# Sandol Auth Relay 기반 챗봇 서버 연동 가이드

이 문서는 Sandol Auth Relay를 활용해 챗봇 서버 인증 플로우를 구축하려는 개발자를 위한 상세 통합 매뉴얼입니다.
보안 배경 지식이 없더라도 이해할 수 있도록 핵심 개념부터 구현 순서까지 단계별로 설명합니다.

---

## 빠른 안내

- **JWT/JWK/Token Exchange가 익숙하지 않다면** 아래 [보안 기초 개념](#보안-기초-개념)을 차근히 읽어 주세요.
- **이미 개념을 모두 알고 있다면** 바로 [구현 가이드](#구현-가이드) 섹션으로 건너뛰어 실제 연동 절차를 확인하시면 됩니다.

---

## 목차

- [보안 기초 개념](#보안-기초-개념)
  - [JWT (JSON Web Token)](#jwt-json-web-token)
  - [JOSE (JSON Object Signing and Encryption)](#jose-json-object-signing-and-encryption)
  - [JWK (JSON Web Key)](#jwk-json-web-key)
  - [Keycloak 기본 용어](#keycloak-기본-용어)
  - [OAuth 2.0과 OpenID Connect](#oauth-20과-openid-connect)
  - [PKCE (Proof Key for Code Exchange)](#pkce-proof-key-for-code-exchange)
  - [Token Exchange (TE)](#token-exchange-te)
  - [Auth Relay가 필요한 이유](#auth-relay가-필요한-이유)
- [구성 요소와 관계](#구성-요소와-관계)
- [구현 가이드](#구현-가이드)
  - [1. 사전 준비](#1-사전-준비)
  - [2. 로그인 링크 발급 (`POST-issueloginlink`)](#2-로그인-링크-발급-post-issueloginlink)
  - [3. 사용자 인증 (`GET-loginlit`)](#3-사용자-인증-get-loginlit)
  - [4. Keycloak 콜백 처리 (`GET-oidccallback`)](#4-keycloak-콜백-처리-get-oidccallback)
  - [5. Token Exchange 수행](#5-token-exchange-수행)
  - [6. 챗봇 서버 자체 토큰 발급](#6-챗봇-서버-자체-토큰-발급)
  - [7. 세션 마무리](#7-세션-마무리)
- [챗봇 서버 구현 체크리스트](#챗봇-서버-구현-체크리스트)
- [언어별 권장 라이브러리](#언어별-권장-라이브러리)
- [보안 모범 사례](#보안-모범-사례)
- [부록: 테스트 및 검증 전략](#부록-테스트-및-검증-전략)
- [마무리](#마무리)

---

## 보안 기초 개념

아래 내용은 Auth Relay를 이해하는 데 필요한 핵심 보안 키워드를 단계별로 정리한 것입니다.  
각 항목은 용어의 뜻, 구성 요소, 실제 사용처를 함께 설명합니다.

### JWT (JSON Web Token)

- **뜻**: 두 시스템이 사용자의 신원이나 권한을 안전하게 교환하기 위해 정의된 토큰 형식입니다. RFC 7519에서 표준화되었습니다.
- **구조**: `Header.Payload.Signature` 세 부분이 Base64URL로 인코딩되어 `xxx.yyy.zzz` 형식으로 전송됩니다.
  - **Header**: 토큰 유형(`typ`), 서명 알고리즘(`alg`) 등의 메타데이터가 포함됩니다.
  - **Payload (Claims)**: 사용자 정보와 만료 시각(`exp`), 발급자(`iss`), 대상(`aud`) 같은 클레임이 담기는 실제 데이터 영역입니다.
  - **Signature**: 헤더와 페이로드를 연결한 문자열에 비밀키 혹은 개인키로 서명한 값입니다. 토큰 위·변조 여부를 판별합니다.
- **클레임 용어 정리**
  - `iss`: 발급자(Issuer)
  - `sub`: 사용자 식별자(Subject)
  - `aud`: 토큰이 유효한 대상(Audience)
  - `exp`, `iat`, `nbf`: 만료, 발급, 사용 가능 시각
- **토큰 종류**
  - **Access Token**: 보호된 API 호출 시 인증 자격으로 사용되는 토큰.
  - **ID Token**: 사용자 정보(ID, 프로필)를 반환하는 토큰. 주로 OpenID Connect에서 사용.
  - **Refresh Token**: Access Token 재발급용 장기 토큰.
- **Auth Relay에서의 사용**
  - Relay는 로그인 진입 토큰(LIT)을 HS256으로 서명하고, 챗봇 서버는 공유된 `JWT_SECRET`으로 이를 검증합니다.

### JOSE (JSON Object Signing and Encryption)

- **뜻**: JWT를 포함해 JSON 기반 전자서명/암호화 방식을 정의한 스펙 모음입니다.
- **주요 구성**
  - **JWS (JSON Web Signature)**: JSON 데이터를 디지털 서명하는 규격. JWT는 JWS 구조를 그대로 사용합니다.
  - **JWE (JSON Web Encryption)**: JSON 데이터를 암호화하는 규격.
  - **JWK (JSON Web Key)**: 키를 JSON으로 표현하는 규격.
  - **JWA (JSON Web Algorithms)**: JWS/JWE에서 사용하는 알고리즘(HS256, RS256 등)을 정의합니다.
- **Auth Relay와의 연관성**
  - Relay가 발급하는 LIT, Keycloak이 발급하는 Access Token 모두 JWS 형식을 따릅니다.
  - 챗봇 서버는 JWK를 사용해 Keycloak의 서명을 검증합니다.

### JWK (JSON Web Key)

- **뜻**: 공개키 또는 대칭키 정보를 JSON 구조로 제공하는 표준 형식입니다.
- **핵심 필드**
  - `kty`: 키 유형(RSA, EC, oct 등)
  - `kid`: 키 식별자(Key ID). 여러 키 중 적절한 키를 선택할 때 사용합니다.
  - `use`: 키 용도(sig: 서명, enc: 암호화)
  - `alg`: 키가 사용되는 알고리즘(예: RS256)
  - `n`, `e`: RSA 공개키 구성 요소(모듈러스, 지수)
- **활용 시나리오**
  - Keycloak은 `/realms/{realm}/protocol/openid-connect/certs`에서 JWK 세트를 제공합니다.
  - 챗봇 서버는 콜백으로 받은 토큰의 `kid`를 확인하고, JWK 세트에서 동일한 `kid`를 가진 공개키로 서명을 검증합니다.

### Keycloak 기본 용어

- **Realm**: 인증 정책, 사용자, 클라이언트 구성이 묶여 있는 보안 경계입니다. 하나의 Realm은 독립된 로그인 공간을 의미합니다.
- **Client**: Keycloak이 토큰을 발급해 주는 대상 애플리케이션입니다. Auth Relay, 챗봇 서버, 기타 마이크로서비스가 각각 하나의 Client로 등록됩니다.
- **Client Secret**: 비공개로 관리되는 클라이언트용 시크릿이며, 토큰 발급 요청 시 클라이언트 인증에 사용됩니다.
- **Redirect URI**: Authorization Code Flow 완료 후 Keycloak이 코드를 전송할 엔드포인트입니다. Relay의 `/relay/oidc/callback`이 여기에 해당합니다.
- **Client Scope / Mapper**: 토큰에 포함될 클레임을 제어하는 Keycloak 구성 요소입니다. Scope를 통해 사용자 프로필, 이메일, 역할 등 필요한 정보를 선택적으로 추가할 수 있습니다.
- **역할 분담**: 실무에서는 보안 담당자가 Realm과 Client를 선행 구성하고, 챗봇 개발자에게 `client_id`, Redirect URI, Scope 목록, 시크릿 등의 정보를 전달하는 방식이 일반적입니다. Auth Relay 설정 역시 보안 담당자가 대신 등록하고 운영하는 경우가 많습니다.

### OAuth 2.0과 OpenID Connect

- **OAuth 2.0 기본 개념**
  - **목적**: 사용자가 직접 자격 증명을 공유하지 않고도 애플리케이션이 특정 리소스에 접근하도록 권한을 위임하는 프레임워크.
  - **주요 역할(Role)**
    - *Resource Owner*: 사용자
    - *Client*: 사용자의 자원을 대신 요청하는 애플리케이션 (챗봇 서버)
    - *Authorization Server*: 인증과 토큰 발급 담당 (Keycloak)
    - *Resource Server*: 보호된 리소스를 제공하는 API 서버
  - **대표 흐름(Grant Type)**
    - Authorization Code, Client Credentials, Resource Owner Password, Implicit 등
    - Auth Relay는 Authorization Code Flow + Token Exchange를 결합해 사용합니다.
- **핵심 용어**
  - **Audience (`aud`)**: 토큰이 접근을 허용하는 대상 서비스 혹은 API입니다. 토큰을 검증하는 서버는 자신이 Audience 목록에 포함되어 있는지 확인해 권한 위임 범위를 판별합니다.
  - **Scope**: 토큰이 허용하는 세부 권한의 집합입니다.
    - **표준 OIDC Scope**
      - `openid`: OpenID Connect 기반 인증을 활성화하는 필수 Scope입니다.
      - `profile`: 이름, 닉네임 등 기본 프로필 정보를 요청합니다.
      - `email`: 사용자 이메일 주소를 요청합니다.
      - `phone`: 전화번호 정보를 요청합니다.
      - `address`: 물리 주소 정보를 요청합니다.
      - `offline_access`: Refresh Token 발급을 요청할 때 사용합니다.
      - `roles` 혹은 `microprofile-jwt`: Keycloak 역할 정보를 포함시킬 때 사용합니다.
    - **권장 최소 Scope**
      - 로그인과 기본 정보 확인에 필요한 최소 구성은 `openid profile email`입니다. 챗봇이 추가 정보를 요구하지 않는다면 이 조합을 사용하세요.
    - **커스텀 Scope**
      - Keycloak 관리자는 `bot:send_message`, `chat:read_history` 등 서비스 맞춤형 Scope를 정의할 수 있습니다.
      - 커스텀 Scope 이름에는 공백 대신 하이픈(`-`)이나 콜론(`:`)을 사용하고, 의미가 명확하도록 도메인을 설계합니다.
      - 챗봇 서버는 Token Exchange 요청 시 필요한 Scope를 정확하게 명시해 최소 권한 원칙을 준수하세요.
    - Scope 문자열은 공백으로 구분된 리스트이며, Keycloak 측에서 허용하지 않은 Scope를 요청하면 오류가 발생합니다.
- **OpenID Connect (OIDC)**
  - OAuth 2.0 위에 사용자 인증을 확장한 프로토콜입니다.
  - Discovery Document(`/.well-known/openid-configuration`), ID Token, UserInfo Endpoint 등을 통해 표준화된 사용자 정보를 제공합니다.
  - Relay는 Keycloak의 OIDC 엔드포인트를 활용해 인가 URL, 토큰 엔드포인트 등을 자동으로 탐색합니다.

### PKCE (Proof Key for Code Exchange)

- **뜻**: Authorization Code가 탈취되는 공격을 방지하기 위해 도입된 추가 검증 메커니즘입니다.
- **작동 원리**
  - 클라이언트는 임의의 난수 문자열 `code_verifier`를 생성합니다.
  - `code_verifier`를 S256(sha256)으로 해시하여 Base64URL로 인코딩한 값을 `code_challenge`로 사용합니다.
  - 인가 요청 시 `code_challenge`와 `code_challenge_method=S256`을 함께 전송합니다.
  - 토큰 교환 시 Keycloak은 전달받은 `code_verifier`로 `code_challenge`를 재계산해 일치 여부를 확인합니다.
- **Auth Relay에서의 역할 분담**
  - Relay가 `code_verifier`, `code_challenge`를 자동으로 생성하고 diskcache에 저장합니다.
  - Keycloak이 이를 검증하며, 챗봇 서버는 별도의 PKCE 처리를 할 필요가 없습니다.
  - 단, 챗봇 서버는 state와 함께 전달받은 값이 만료되기 전에 Token Exchange를 완료할 수 있도록 전체 흐름을 빠르게 연결해야 합니다.

### Token Exchange (TE)

- **뜻**: 기존 토큰을 새로운 속성(Audience, Scope 등)을 가진 토큰으로 교환하는 OAuth 2.0 확장 규격(RFC 8693)입니다.
- **동작 방식**
  - 클라이언트가 `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`로 요청을 전송합니다.
  - `subject_token`에 기존 Access Token을, `audience`에 새 토큰이 유효해야 할 대상 서비스를 명시합니다.
  - Authorization Server(Keycloak)는 정책에 따라 새로운 토큰을 발급하거나 거절합니다.
- **Audience/Scope가 중요한 이유**
  - Authorization Code Flow로 발급받은 최초 Access Token의 Audience는 Relay 또는 Keycloak 기본 서비스일 수 있습니다. 챗봇 서버가 자체 API를 보호하려면 자신을 Audience로 포함하는 토큰이 필요합니다.
  - Scope를 통해 챗봇 서버가 수행할 수 있는 작업(예: 메시지 전송, 사용자 정보 조회)을 제한하거나 확장할 수 있습니다. Token Exchange 과정에서 필요한 Scope를 명시하여 최소 권한 원칙을 지킬 수 있습니다.
- **주요 파라미터 설명**
  - `subject_token_type`: `subject_token`의 종류를 나타내며, 대표적으로 아래 값이 사용됩니다.
    - `urn:ietf:params:oauth:token-type:access_token` (기본 Access Token)
    - `urn:ietf:params:oauth:token-type:id_token`
    - `urn:ietf:params:oauth:token-type:refresh_token`
    - `urn:ietf:params:oauth:token-type:saml2` (SAML2 어설션)
    - 모든 값은 `urn:ietf:params:oauth:token-type:` 접두사를 따르며, 토큰의 형태에 따라 명확히 구분됩니다. 실제 토큰 유형과 값이 일치하지 않으면 Keycloak이 요청을 거부합니다.
  - `requested_token_type`: 새로 받고 싶은 토큰 유형을 지정합니다. 명시하지 않으면 Access Token이 기본값입니다.
  - `scope`: 새 토큰에 포함할 권한 목록을 추가 지정합니다.
  - `resource` / `audience`: 토큰이 사용할 서비스 URI 혹은 클라이언트 ID입니다.
- **Auth Relay 시나리오**
  - Relay는 Keycloak으로부터 받은 Access Token을 챗봇 서버에 전달합니다.
  - 최초 Access Token의 Audience는 Relay 자신으로 설정되어 있으므로, 챗봇 서버는 Token Exchange를 통해 Audience를 챗봇 서버(Client)로 변경하고 필요한 Scope를 확장합니다.
  - Keycloak 관점에서 Authorization Code를 요청한 주체는 Auth Relay의 `client_id`이므로, Token Exchange 없이 해당 Access Token을 챗봇 서버가 직접 사용할 수 없습니다.
  - Token Exchange 결과로 발급된 토큰을 내부 API 호출 또는 추가 인증 토큰 발급의 근거로 사용합니다.

### Auth Relay가 필요한 이유

- **브라우저 기반 인증의 한계 극복**
  - 챗봇 서비스는 사용자가 모바일 메신저나 음성 인터페이스에서 상호작용하는 경우가 많습니다. 이 환경에서는 Authorization Code Flow에서 요구하는 브라우저 리다이렉트와 콜백 처리를 직접 수행하기 어렵습니다.
  - Auth Relay 도입 전에는 챗봇 서버가 사용자를 웹 브라우저로 전환시키고, 복잡한 리다이렉트 URL과 state 값을 직접 관리해야 했습니다. 이는 사용자 경험을 해치고, 보안 측면에서도 관리가 어렵습니다.
- **도입 전후 비교**
  - *Relay 이전*: 챗봇 서버가 인가 URL을 생성해 사용자에게 전달 → 사용자가 Keycloak 인증 후 챗봇 서버의 콜백 URL로 돌아와야 함 → 챗봇 서버가 PKCE, state, 사용자 매핑을 직접 처리해야 함 → 챗봇 UI와 웹 브라우저 간 상태 동기화가 복잡.
  - *Relay 이후*: 챗봇 서버는 Relay에 로그인 링크 발급만 요청 → 사용자는 Relay가 제공하는 URL을 통해 Keycloak 인증 → Relay가 모든 PKCE/state 처리를 마치고 토큰을 챗봇 서버로 전달 → 챗봇 서버는 Token Exchange와 후속 로직에 집중.
- **필수 구성 요소**
  - Relay는 단순한 편의 기능이 아니라, 브라우저 기반 인증을 챗봇 환경에 맞게 중계하는 필수 요소입니다. 챗봇 서버가 직접 Authorization Code Flow를 수행하기 어려운 환경(모바일 메신저, 음성 인터페이스 등)에서 Relay가 사실상 유일한 대안입니다.
- **추가 이점**
  - 보안 경계 분리: PKCE, state, nonce 등 민감한 로직을 Relay가 담당해 챗봇 서버의 공격 면적을 줄입니다.
  - 일관된 인증 흐름: 여러 챗봇 플랫폼에서 동일한 Keycloak 플로우를 재사용할 수 있도록 공통 진입점을 제공합니다.
  - 신뢰할 수 있는 전달자: Relay가 Access Token을 검증한 뒤 HMAC 서명과 함께 챗봇 서버로 전달하므로 중간 탈취 위험을 완화합니다.
  - 운영 편의성: Keycloak 설정 변경이나 클라이언트 추가가 필요할 때 Relay 한 곳만 수정하면 되며, 챗봇 서버는 최소한의 변경으로 연동할 수 있습니다.
  - 감사 및 로깅: Relay 레이어에서 모든 인증 요청을 일괄 로깅해 감사와 문제 해결을 쉽게 만듭니다.

---

## 구성 요소와 관계

다음 네 가지 주요 컴포넌트가 상호 작용합니다.

1. **사용자 + 챗봇 UI**: 로그인 링크를 받아 브라우저로 이동합니다.
2. **챗봇 서버**: 사용자의 ID와 콜백 URL 등을 바탕으로 Auth Relay에 로그인 링크 발급을 요청하고, Relay로부터 받은 Access Token으로 Token Exchange를 진행합니다.
3. **Auth Relay**: Keycloak과 통신해 Authorization Code Flow를 대신 수행하고, Access Token을 챗봇 서버에 전달합니다.
4. **Keycloak**: 사용자 인증 및 토큰 발급을 담당하는 IdP(Identity Provider)입니다.

```
사용자 ─(로그인 링크)─▶ 브라우저 ─▶ Auth Relay ─▶ Keycloak
   ▲                               │            │
   │                               ▼            ▼
챗봇 UI ◀────── 챗봇 서버 ◀──── Access Token ◀───┘
                      │
                      └─(Token Exchange)→ 신규 토큰 발급
```

`temp-web-service`는 챗봇 서버를 모사한 참고 예시이며, 실제 구축 시 아래 구현 가이드를 기준으로 각 언어/프레임워크에 맞춰 개발하면 됩니다.

---

## 구현 가이드

### 1. 사전 준비

실무에서는 보안 담당자 혹은 플랫폼 팀이 Keycloak과 Auth Relay 설정을 선행 구성하고, 챗봇 개발자에게 필요한 값(Client ID, Redirect URI, Scope, 시크릿 등)을 전달하는 경우가 많습니다. 아래 항목을 점검하면서 담당자와 정보를 미리 조율하세요.

1. **Keycloak 설정**
   - Realm, Client를 생성하고 Redirect URI에 `https://<relay-domain>/relay/oidc/callback`을 등록합니다.
   - 필요한 Scope, Role, Token Exchange 설정 등을 구성합니다.
2. **Auth Relay 설정**
   - `app/config/clients.json`에 클라이언트 정보를 등록합니다.
   - `client_secret`은 가능한 환경 변수(`CLIENT_KEY__SECRETS`)로 주입하세요.
3. **챗봇 서버 설정**
   - Relay가 POST를 보낼 콜백 엔드포인트를 준비합니다.
   - `RELAY_TO_CHATBOT_HMAC_SECRET`과 동일한 값을 서버에서 보관해 서명 검증에 사용합니다.
   - Token Exchange를 수행할 Keycloak 클라이언트 시크릿/권한을 확보합니다.

### 2. 로그인 링크 발급 (`POST /issue_login_link`)

1. 챗봇 서버는 사용자 세션을 생성할 때 아래 정보를 Relay에 전송합니다.
   - `chatbot_user_id`: 챗봇 내부 사용자 식별자
   - `callback_url`: Relay가 Access Token을 전달할 챗봇 서버 엔드포인트
   - `client_key`: `clients.json`에 등록된 키
   - `redirect_after`: 인증 성공 후 사용자를 이동시킬 경로 (Relay allowlist에 포함되어야 함)
2. 응답으로 `login_link`와 `expires_in`을 받습니다.
3. 챗봇 UI는 사용자의 브라우저를 이 링크로 안내합니다.

### 3. 사용자 인증 (`GET /login/{lit}`)

1. 사용자가 링크에 접근하면 Relay는 LIT(Login Initiation Token)을 검증합니다.
2. Relay는 PKCE(state/nonce/code_verifier)를 준비하고 Keycloak 인가 엔드포인트로 리다이렉트합니다.
3. 사용자는 Keycloak 로그인 페이지에서 자격 증명을 입력합니다.

### 4. Keycloak 콜백 처리 (`GET /oidc/callback`)

1. Keycloak은 Authorization Code와 state를 Relay로 전달합니다.
2. Relay는 state/nonce를 검증하고 Token Endpoint로 Access Token을 교환합니다.
3. Relay는 Access Token과 메타데이터를 챗봇 서버의 `callback_url`로 POST합니다.
   - 페이로드 필드: `relay_access_token`, `issuer`, `aud`, `chatbot_user_id`, `client_key`, `ts`, `nonce`
   - 헤더: `X-Relay-Signature` (HMAC-SHA256)
4. 챗봇 서버는 서명을 검증해 메시지 위·변조 여부를 확인합니다.

### 5. Token Exchange 수행

1. 챗봇 서버는 Keycloak Token Endpoint에 `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`로 요청합니다.
2. 필수 파라미터
   - `subject_token`: Relay가 전달한 `relay_access_token`
   - `subject_token_type`: `urn:ietf:params:oauth:token-type:access_token`
   - `audience`: 챗봇 서버가 사용하고자 하는 대상 클라이언트 ID
   - 필요 시 `requested_token_type`, `scope` 등을 추가합니다.
3. 응답으로 신규 Access Token(또는 Refresh Token)을 수신합니다.
4. 이 토큰에 대한 유효성 검사는 Keycloak의 JWK로 진행합니다.

### 6. 챗봇 서버 자체 토큰 발급

Token Exchange로 받은 토큰을 바로 사용할 수도 있지만, 내부 시스템 간 통신에는 자체 JWT를 발급하는 경우가 많습니다.

1. Keycloak이 발급한 토큰의 `sub`, `aud`, `exp` 등의 클레임을 검증합니다.
2. 내부 서비스 정책에 맞춰 토큰을 재구성합니다.
   - 예: `user_id`, `roles`, `session_id`, `issued_at`, `expires_at`
3. 내부 서명 키(대칭 혹은 비대칭)를 사용해 JWT를 발급합니다.
4. 클라이언트(챗봇 UI 또는 후속 서비스)에 이 토큰을 저장/전송해 인증 상태를 유지합니다.

#### 만료 대응 전략

- **Token Exchange 재호출**: 자체 JWT가 만료되기 전에 Relay에서 전달받은 Refresh Token이나 저장된 Token Exchange 결과를 사용해 다시 Token Exchange를 수행합니다. Refresh Token을 사용하지 않는 경우에는 사용자를 로그인 플로우로 재유도해야 합니다.
- **슬라이딩 세션 적용**: 내부 JWT 만료 시각을 외부 Access Token 만료보다 짧게 설정하고, 갱신 시점에 외부 토큰의 유효성을 함께 검증합니다.
- **예외 처리**: 만료된 JWT로 내부 API 호출 시 401/403 응답을 감지하고, 챗봇 클라이언트에게 재인증을 안내합니다. 자동 재시도를 구현하더라도 일정 횟수 이후에는 사용자 행동을 요청해야 합니다.
- **로그 추적**: 토큰 만료와 재발급 이벤트를 감사 로그에 기록해 이상 징후를 신속히 파악합니다.

### 7. 세션 마무리

1. Relay의 세션은 Token Exchange를 완료하면 자동으로 만료되지만, 챗봇 서버에서 불필요하게 오래 보관하지 않도록 주기적으로 정리합니다.
2. 사용자가 로그아웃하면 Keycloak RP-initiated Logout 또는 세션 무효화를 고려합니다.

---

## 챗봇 서버 구현 체크리스트

1. **서명 검증**
   - Relay의 `X-Relay-Signature`를 `RELAY_TO_CHATBOT_HMAC_SECRET`으로 검증해야 합니다.
   - 타임스탬프(`ts`)를 확인해 재전송 공격을 방지합니다.
2. **Token Exchange 요청**
   - TLS(HTTPS) 환경에서만 호출합니다.
   - 필요한 Scope와 Audience를 Keycloak 관리자와 협업해 정의합니다.
3. **토큰 캐싱**
   - Token Exchange 결과를 적절한 기간 캐싱하고, 만료 시 재교환합니다.
4. **오류 처리**
   - Relay로부터 `callback_failed` 응답을 받았을 때 사용자에게 재시도를 안내합니다.
5. **감사 로그**
   - 사용자 ID, 요청 시간, 발급된 토큰 식별자 등을 기록합니다.

---

## 언어별 권장 라이브러리

- **Python**
  - `python-keycloak`: Keycloak Token Exchange, 사용자 관리 기능 지원.
  - `Authlib`: OAuth 2.0 / OpenID Connect 클라이언트 구현에 활용 가능.
- **Node.js**
  - `openid-client`: 공식 OpenID Foundation 지원 라이브러리, Token Exchange 구현 가능.
  - `keycloak-connect`: Express 기반 Keycloak 어댑터(필요에 따라 활용).
- **Java (Spring)**
  - `spring-security-oauth2-client`: OAuth 2.0 클라이언트 기능.
  - `org.keycloak:keycloak-admin-client` 또는 `keycloak-authz-client`: Token Exchange API 호출에 활용.

이 라이브러리들은 HTTP 요청, 토큰 파싱/검증을 추상화해 개발자가 비즈니스 로직에 집중하도록 도와줍니다.

---

## 보안 모범 사례

1. **환경 변수 관리**
   - `client_secret`, `RELAY_TO_CHATBOT_HMAC_SECRET` 등 민감 정보는 팀간의 약속된 방법으로만 안전하게 관리합니다.
2. **HTTPS 강제**
   - Relay, 챗봇 서버, Keycloak 모두 TLS를 활성화합니다.
3. **탈취 방지**
   - Access Token은 메모리/로그에 남기지 않고, 필요 시 마스킹하거나 암호화합니다.
4. **권한 최소화**
   - Keycloak에서 Token Exchange 대상 클라이언트에 최소한의 Scope만 부여합니다.
5. **재전송 방어**
   - Relay 콜백의 `nonce`와 `ts`를 저장해, 동일한 요청이 다시 들어오면 거부합니다.

---

## 부록: 테스트 및 검증 전략

1. **temp-web-service 활용**
   - 레포지토리에 포함된 샘플을 참고해 전체 플로우를 로컬에서 재현할 수 있습니다.
2. **단계별 점검**
   - 로그인 링크 발급 → Keycloak 인증 → Relay 콜백 → Token Exchange → 내부 JWT 발급 순으로 단위 테스트를 작성합니다.
3. **로그 관찰**
   - Relay와 Keycloak 로그를 함께 확인해 인증 실패 원인을 빠르게 파악합니다.
4. **부하 테스트**
   - FanoutCache 디렉터리를 공유한 상태에서 다중 워커 환경(Uvicorn `--workers`)으로 부하 테스트를 진행해 세션 처리 안정성을 검증합니다.

---

## 마무리

이 가이드를 바탕으로 챗봇 서버는 Auth Relay를 중심으로 Keycloak 인증 흐름을 안전하고 일관되게 관리할 수 있습니다.
필요한 경우 temp-web-service 예제를 확장해 자동화 테스트나 모의 챗봇 서버를 구축하는 것도 추천드립니다.

추가 문의나 개선 아이디어가 있다면 Sandol Auth Relay 팀에 공유해 주세요.
