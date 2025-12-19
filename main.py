"""Sandol의 메인 애플리케이션 파일입니다."""

from contextlib import asynccontextmanager
import traceback

from fastapi import FastAPI, Request
import uvicorn

from app.routers import auth_relay_router
from app.config import logger
from app.utils.clients import client_registry_init


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI의 lifespan 이벤트 핸들러"""
    logger.info("🚀 서비스 시작:")
    client_registry = client_registry_init()
    client_registry.validate()

    yield  # FastAPI가 실행 중인 동안 유지됨

    # 애플리케이션 종료 시 로그 출력
    logger.info("🛑 서비스 종료:")


# lifespan 적용
app = FastAPI(title="Auth Relay", lifespan=lifespan, root_path="/relay")
app.include_router(auth_relay_router)


@app.get("/")
async def root():
    """루트 엔드포인트입니다."""
    logger.info("Root endpoint accessed")
    return {"test": "Hello Sandol"}


@app.get("/health")
async def health_check():
    """헬스 체크 엔드포인트입니다."""
    return {"status": "ok"}


@app.exception_handler(Exception)
async def http_exception_handler(request: Request, exc: Exception):
    """HTTPException 핸들러입니다."""
    # 예외 처리 시 로그 남기기
    logger.error(
        "Exception occurred: %s\n%s"
        % (exc, "".join(traceback.format_tb(exc.__traceback__)))
    )
    raise exc  # 기본 예외 처리로 전달


if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 5600

    logger.info("Starting Sandol Auth Relay server on %s:%s", HOST, PORT)
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)
