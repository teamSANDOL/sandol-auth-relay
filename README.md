# Auth-Relay (python-keycloak + PyJWT)

## 개요

- Keycloak 인가 콜백을 relay가 처리하고, code→access_token 교환 후
- 챗봇 서버에 access_token(=subject_token)을 POST로 전달
- 챗봇 서버는 Token Exchange(client_secret)로 자체 오디언스 토큰을 획득

## 엔드포인트

- POST /issue_login_link
- GET  /login/{lit}
- GET  /oidc/callback

## 환경변수

- BASE_URL, JWT_SECRET, RELAY_TO_CHATBOT_HMAC_SECRET 등

## 실행

```bash
uvicorn app.main:app --reload --port 8080
```
