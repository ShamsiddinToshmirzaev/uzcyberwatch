"""Kampaniya grafini qurish va jamoalar aniqlash.

TZ: FT-26 — Neo4j da infratuzilma grafini saqlash va Louvain
algoritmi bilan bog'liq fishing domenlarini kampaniyalarga
klasterlash. Bu passiv tahlil; aktiv skanerlash taqiqlangan (HT-07).
"""
from __future__ import annotations

import asyncio
import os

import networkx as nx

try:
    import community as _louvain  # python-louvain
    _HAS_LOUVAIN = True
except ImportError:  # pragma: no cover
    _HAS_LOUVAIN = False

try:
    from neo4j import GraphDatabase
    _HAS_NEO4J = True
except ImportError:  # pragma: no cover
    _HAS_NEO4J = False


NEO4J_URI  = os.environ.get("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "neo4j")


def detect_communities(g: nx.Graph) -> dict[str, int]:
    """Louvain algoritmi yordamida fishing kampaniyalarini aniqlash.

    Agar python-louvain o'rnatilmagan bo'lsa, ulanmagan komponentlar
    alohida jamoa sifatida qaytariladi (fallback).

    Returns:
        {tugun_nomi: jamoa_id} — jamoa_id butun son (0 dan boshlanadi).
    """
    if g.number_of_nodes() == 0:
        return {}
    if _HAS_LOUVAIN:
        return _louvain.best_partition(g)
    # Fallback: har bir ulanmagan komponent → alohida jamoa
    return {n: i for i, comp in enumerate(nx.connected_components(g)) for n in comp}


class GraphAnalyser:
    """Neo4j grafiga kiritish va Louvain kampaniya klasterlash (FT-26)."""

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        self._uri  = uri or NEO4J_URI
        self._user = user or NEO4J_USER
        self._pass = password or NEO4J_PASS
        self._driver = None

    # ----------------------------------------------------------------- driver

    def _get_driver(self):
        if self._driver is None:
            if not _HAS_NEO4J:
                raise RuntimeError("neo4j kutubxonasi o'rnatilmagan")  # pragma: no cover
            self._driver = GraphDatabase.driver(
                self._uri, auth=(self._user, self._pass)
            )
        return self._driver

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    # ----------------------------------------------------------------- yozish

    def _run_write(self, cypher: str, **params) -> None:
        with self._get_driver().session() as session:
            session.run(cypher, **params)

    def upsert_domain(
        self,
        domain: str,
        risk_score: int = 0,
        cert_issuer: str | None = None,
    ) -> None:
        """Domain tugunini qo'shish yoki yangilash (FT-26)."""
        self._run_write(
            "MERGE (d:Domain {name: $name}) "
            "SET d.risk_score = $risk, d.cert_issuer = $issuer",
            name=domain,
            risk=risk_score,
            issuer=cert_issuer,
        )

    def upsert_ip(
        self,
        ip: str,
        asn: str | None = None,
        country: str | None = None,
    ) -> None:
        """IP tugunini qo'shish yoki yangilash (FT-26)."""
        self._run_write(
            "MERGE (i:IpAddr {value: $ip}) "
            "SET i.asn = $asn, i.country = $country",
            ip=ip,
            asn=asn,
            country=country,
        )

    def link_domain_to_ip(self, domain: str, ip: str) -> None:
        """Domain → IP 'RESOLVES_TO' bog'lanishi (FT-26)."""
        self._run_write(
            "MATCH (d:Domain {name: $domain}), (i:IpAddr {value: $ip}) "
            "MERGE (d)-[:RESOLVES_TO]->(i)",
            domain=domain,
            ip=ip,
        )

    def link_domains(
        self,
        domain_a: str,
        domain_b: str,
        relation: str = "SIMILAR_PHASH",
    ) -> None:
        """Ikki domain o'rtasida to'g'ridan-to'g'ri bog'lanish (FT-26)."""
        self._run_write(
            f"MATCH (a:Domain {{name: $a}}), (b:Domain {{name: $b}}) "
            f"MERGE (a)-[:{relation}]->(b)",
            a=domain_a,
            b=domain_b,
        )

    # ----------------------------------------------------------------- o'qish

    def build_nx_graph(self) -> nx.Graph:
        """Neo4j dan tugun va qirralarni o'qib NetworkX grafini qurish (FT-26).

        Graf ikki xil qirra manbasini birlashtiradi:
        1. Bir xil IP ga ishora qiluvchi domenlar (RESOLVES_TO transitivligi).
        2. To'g'ridan-to'g'ri Domain–Domain bog'lanishlar (SIMILAR_PHASH va h.k.).
        """
        g = nx.Graph()
        with self._get_driver().session() as session:
            for rec in session.run(
                "MATCH (d:Domain) RETURN d.name AS name, d.risk_score AS risk"
            ):
                g.add_node(rec["name"], risk=rec["risk"] or 0)

            for rec in session.run(
                "MATCH (a:Domain)-[:RESOLVES_TO]->(i:IpAddr)<-[:RESOLVES_TO]-(b:Domain) "
                "WHERE a.name < b.name "
                "RETURN a.name AS src, b.name AS dst"
            ):
                g.add_edge(rec["src"], rec["dst"])

            for rec in session.run(
                "MATCH (a:Domain)-[r]->(b:Domain) "
                "WHERE a.name < b.name "
                "RETURN a.name AS src, b.name AS dst"
            ):
                g.add_edge(rec["src"], rec["dst"])

        return g

    def find_related(self, node_id: str, depth: int = 2) -> list[str]:
        """Ko'rsatilgan chuqurlikda bog'liq tugunlarni Neo4j orqali topish."""
        with self._get_driver().session() as session:
            result = session.run(
                "MATCH (start {name: $node})-[*1..$depth]-(related) "
                "WHERE related.name IS NOT NULL AND related.name <> $node "
                "RETURN DISTINCT related.name AS name",
                node=node_id,
                depth=depth,
            )
            return [rec["name"] for rec in result]

    def get_campaign_id(self, node_id: str) -> int | None:
        """Berilgan domain uchun kampaniya (Louvain jamoa) ID sini qaytarish."""
        try:
            g = self.build_nx_graph()
        except Exception:
            return None
        if node_id not in g:
            return None
        return detect_communities(g).get(node_id)

    def stats(self) -> dict[str, int]:
        """Graf statistikasi: tugunlar, qirralar, kampaniyalar soni."""
        try:
            g = self.build_nx_graph()
        except Exception:
            return {"node_count": 0, "edge_count": 0, "community_count": 0}
        partition = detect_communities(g)
        return {
            "node_count": g.number_of_nodes(),
            "edge_count": g.number_of_edges(),
            "community_count": len(set(partition.values())),
        }

    # ----------------------------------------------------------------- async

    async def async_upsert_domain(
        self,
        domain: str,
        risk_score: int = 0,
        cert_issuer: str | None = None,
    ) -> None:
        await asyncio.to_thread(self.upsert_domain, domain, risk_score, cert_issuer)

    async def async_upsert_ip(
        self,
        ip: str,
        asn: str | None = None,
        country: str | None = None,
    ) -> None:
        await asyncio.to_thread(self.upsert_ip, ip, asn, country)

    async def async_build_nx_graph(self) -> nx.Graph:
        return await asyncio.to_thread(self.build_nx_graph)

    async def async_stats(self) -> dict[str, int]:
        return await asyncio.to_thread(self.stats)
