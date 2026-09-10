"""Liveness/readiness tekshiruvi. FT-46."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app import __version__

router = APIRouter(tags=["system"])


class HealthResponse(BaseModel):
    status:  str
    version: str


@router.get("/health", response_model=HealthResponse, summary="Liveness tekshiruvi")
async def health() -> HealthResponse:
    """Ilova ishlayotganligini tekshiradi."""
    return HealthResponse(status="ok", version=__version__)
