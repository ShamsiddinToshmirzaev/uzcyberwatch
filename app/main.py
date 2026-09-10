"""UzCyberWatch — FastAPI asosiy ilova.

TZ: FT-46. Barcha routerlarni birlashtiradi, middleware va lifespan
sozlaydi. DB ulanishi startup da ochiladi, shutdown da yopiladi.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import analyse, cases, health
from app.db import close_engine


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown: DB ulanishlarini boshqaradi."""
    yield
    await close_engine()


app = FastAPI(
    title="UzCyberWatch API",
    version=__version__,
    description=(
        "O'zbekiston hududidagi kiberjinoyatlarni avtomatik aniqlash "
        "va tahlil qilish tizimi. Magistrlik dissertatsiyasi amaliy qismi."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — faqat dev muhitida ochiq; prod da .env dan o'qish tavsiya etiladi
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)

# ----------------------------------------------------------------- routerlar

app.include_router(health.router)
app.include_router(analyse.router, prefix="/api/v1")
app.include_router(cases.router,   prefix="/api/v1")
