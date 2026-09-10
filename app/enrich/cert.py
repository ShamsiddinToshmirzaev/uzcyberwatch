"""SSL sertifikat emitenti boyitish moduli. FT-17.

Domen → sertifikat emitenti nomi (Let's Encrypt, DigiCert va b.).
HT-07: passiv — faqat TLS handshake, hujum yo'q.
"""
from __future__ import annotations

import asyncio
import socket
import ssl


def _sync_get_cert_issuer(hostname: str, port: int = 443, timeout: float = 5.0) -> str | None:
    """SSL sertifikat emitentini aniqlaydi. asyncio.to_thread orqali chaqiriladi."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                issuer_fields = dict(x[0] for x in cert.get("issuer", []))
                return (
                    issuer_fields.get("organizationName")
                    or issuer_fields.get("commonName")
                )
    except Exception:
        return None


async def get_cert_issuer(hostname: str, port: int = 443) -> str | None:
    """Asinxron SSL sertifikat emitentini aniqlaydi. FT-17."""
    return await asyncio.to_thread(_sync_get_cert_issuer, hostname, port)
