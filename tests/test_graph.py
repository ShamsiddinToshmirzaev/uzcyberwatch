"""app/detect/graph.py sinovlari (TZ: FT-26, NFT-11).

Neo4j ulanishi mock qilinadi — haqiqiy baza shart emas.
NetworkX va Louvain haqiqiy ishlatiladi (sof funksiya sinovlari).
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import MagicMock, patch, call

import networkx as nx
import pytest

from app.detect.graph import GraphAnalyser, detect_communities


def _run(coro):
    return asyncio.run(coro)


# ----------------------------------------------------------------- yordamchi

def _make_driver(*record_sets):
    """Neo4j driver mock.

    record_sets — har bir session.run() chaqiruvi uchun Record ro'yxati.
    """
    mock_driver = MagicMock()
    mock_session = MagicMock()

    # `with driver.session() as session:` uchun context manager
    mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

    if record_sets:
        mock_session.run.side_effect = [list(recs) for recs in record_sets]
    else:
        mock_session.run.return_value = []

    return mock_driver, mock_session


def _rec(**kwargs):
    """Oddiy Neo4j Record taqlidi."""
    m = MagicMock()
    m.__getitem__ = lambda self, key: kwargs[key]
    return m


# ================================================================= detect_communities

class TestDetectCommunities:
    def test_empty_graph_returns_empty(self):
        g = nx.Graph()
        assert detect_communities(g) == {}

    def test_single_node_one_community(self):
        g = nx.Graph()
        g.add_node("a.uz")
        result = detect_communities(g)
        assert "a.uz" in result
        assert isinstance(result["a.uz"], int)

    def test_two_isolated_nodes_different_communities(self):
        g = nx.Graph()
        g.add_node("a.uz")
        g.add_node("b.uz")
        result = detect_communities(g)
        assert result["a.uz"] != result["b.uz"]

    def test_two_connected_nodes_same_community(self):
        g = nx.Graph()
        g.add_edge("a.uz", "b.uz")
        result = detect_communities(g)
        assert result["a.uz"] == result["b.uz"]

    def test_triangle_same_community(self):
        g = nx.Graph()
        g.add_edges_from([("a.uz", "b.uz"), ("b.uz", "c.uz"), ("a.uz", "c.uz")])
        result = detect_communities(g)
        assert result["a.uz"] == result["b.uz"] == result["c.uz"]

    def test_two_disconnected_triangles(self):
        g = nx.Graph()
        g.add_edges_from([("a.uz", "b.uz"), ("b.uz", "c.uz"), ("a.uz", "c.uz")])
        g.add_edges_from([("x.uz", "y.uz"), ("y.uz", "z.uz"), ("x.uz", "z.uz")])
        result = detect_communities(g)
        # Ikki klaster turli ID ga ega bo'lishi kerak
        abc = {result["a.uz"], result["b.uz"], result["c.uz"]}
        xyz = {result["x.uz"], result["y.uz"], result["z.uz"]}
        assert len(abc) == 1
        assert len(xyz) == 1
        assert abc != xyz

    def test_all_values_are_ints(self):
        g = nx.Graph()
        g.add_edges_from([("p.uz", "q.uz"), ("q.uz", "r.uz")])
        result = detect_communities(g)
        assert all(isinstance(v, int) for v in result.values())


# ================================================================= GraphAnalyser — init

class TestGraphAnalyserInit:
    def test_default_uri_from_env(self):
        with patch.dict(os.environ, {"NEO4J_URI": "bolt://myhost:7687"}):
            from importlib import reload
            import app.detect.graph as gmod
            reload(gmod)
            ga = gmod.GraphAnalyser()
        assert "myhost" in ga._uri

    def test_custom_uri_passed(self):
        ga = GraphAnalyser(uri="bolt://custom:7687")
        assert ga._uri == "bolt://custom:7687"

    def test_driver_initially_none(self):
        ga = GraphAnalyser()
        assert ga._driver is None

    def test_close_noop_when_no_driver(self):
        ga = GraphAnalyser()
        ga.close()  # istisno tashqariga chiqmasligi kerak
        assert ga._driver is None

    def test_close_sets_driver_to_none(self):
        ga = GraphAnalyser()
        mock_driver = MagicMock()
        ga._driver = mock_driver
        ga.close()
        assert ga._driver is None
        mock_driver.close.assert_called_once()


# ================================================================= upsert_domain

class TestUpsertDomain:
    @patch("app.detect.graph.GraphDatabase")
    def test_merge_cypher_called(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.upsert_domain("phish.uz", risk_score=75)

        cypher = mock_sess.run.call_args[0][0]
        assert "MERGE" in cypher
        assert "Domain" in cypher

    @patch("app.detect.graph.GraphDatabase")
    def test_risk_score_passed(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.upsert_domain("phish.uz", risk_score=80)

        kwargs = mock_sess.run.call_args[1]
        assert kwargs.get("risk") == 80

    @patch("app.detect.graph.GraphDatabase")
    def test_cert_issuer_passed(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.upsert_domain("phish.uz", cert_issuer="ZeroSSL")

        kwargs = mock_sess.run.call_args[1]
        assert kwargs.get("issuer") == "ZeroSSL"

    @patch("app.detect.graph.GraphDatabase")
    def test_domain_name_passed(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.upsert_domain("kapitalbnk.uz")

        kwargs = mock_sess.run.call_args[1]
        assert kwargs.get("name") == "kapitalbnk.uz"


# ================================================================= upsert_ip

class TestUpsertIp:
    @patch("app.detect.graph.GraphDatabase")
    def test_merge_ip_cypher_called(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.upsert_ip("192.0.2.1")

        cypher = mock_sess.run.call_args[0][0]
        assert "IpAddr" in cypher
        assert "MERGE" in cypher

    @patch("app.detect.graph.GraphDatabase")
    def test_asn_country_passed(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.upsert_ip("192.0.2.1", asn="AS12345", country="UZ")

        kwargs = mock_sess.run.call_args[1]
        assert kwargs.get("asn") == "AS12345"
        assert kwargs.get("country") == "UZ"


# ================================================================= link_domain_to_ip

class TestLinkDomainToIp:
    @patch("app.detect.graph.GraphDatabase")
    def test_resolves_to_relation_created(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.link_domain_to_ip("phish.uz", "192.0.2.1")

        cypher = mock_sess.run.call_args[0][0]
        assert "RESOLVES_TO" in cypher

    @patch("app.detect.graph.GraphDatabase")
    def test_domain_and_ip_passed(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.link_domain_to_ip("phish.uz", "10.0.0.1")

        kwargs = mock_sess.run.call_args[1]
        assert kwargs.get("domain") == "phish.uz"
        assert kwargs.get("ip") == "10.0.0.1"


# ================================================================= link_domains

class TestLinkDomains:
    @patch("app.detect.graph.GraphDatabase")
    def test_default_similar_phash_relation(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.link_domains("a.uz", "b.uz")

        cypher = mock_sess.run.call_args[0][0]
        assert "SIMILAR_PHASH" in cypher

    @patch("app.detect.graph.GraphDatabase")
    def test_custom_relation_type(self, mock_gdb):
        mock_drv, mock_sess = _make_driver()
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.link_domains("a.uz", "b.uz", relation="SAME_CAMPAIGN")

        cypher = mock_sess.run.call_args[0][0]
        assert "SAME_CAMPAIGN" in cypher


# ================================================================= build_nx_graph

class TestBuildNxGraph:
    @patch("app.detect.graph.GraphDatabase")
    def test_returns_nx_graph(self, mock_gdb):
        mock_drv, mock_sess = _make_driver([], [], [])
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        g = ga.build_nx_graph()
        assert isinstance(g, nx.Graph)

    @patch("app.detect.graph.GraphDatabase")
    def test_domain_nodes_added(self, mock_gdb):
        nodes = [_rec(name="a.uz", risk=50), _rec(name="b.uz", risk=30)]
        mock_drv, mock_sess = _make_driver(nodes, [], [])
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        g = ga.build_nx_graph()
        assert "a.uz" in g.nodes
        assert "b.uz" in g.nodes

    @patch("app.detect.graph.GraphDatabase")
    def test_shared_ip_creates_edge(self, mock_gdb):
        nodes = [_rec(name="a.uz", risk=50), _rec(name="b.uz", risk=60)]
        shared_ip_edges = [_rec(src="a.uz", dst="b.uz")]
        mock_drv, mock_sess = _make_driver(nodes, shared_ip_edges, [])
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        g = ga.build_nx_graph()
        assert g.has_edge("a.uz", "b.uz")

    @patch("app.detect.graph.GraphDatabase")
    def test_empty_db_empty_graph(self, mock_gdb):
        mock_drv, mock_sess = _make_driver([], [], [])
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        g = ga.build_nx_graph()
        assert g.number_of_nodes() == 0

    @patch("app.detect.graph.GraphDatabase")
    def test_direct_domain_edges_added(self, mock_gdb):
        nodes = [_rec(name="a.uz", risk=40), _rec(name="c.uz", risk=55)]
        direct_edges = [_rec(src="a.uz", dst="c.uz")]
        mock_drv, mock_sess = _make_driver(nodes, [], direct_edges)
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        g = ga.build_nx_graph()
        assert g.has_edge("a.uz", "c.uz")


# ================================================================= find_related

class TestFindRelated:
    @patch("app.detect.graph.GraphDatabase")
    def test_returns_list(self, mock_gdb):
        mock_drv, mock_sess = _make_driver([_rec(name="b.uz")])
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        result = ga.find_related("a.uz")
        assert isinstance(result, list)

    @patch("app.detect.graph.GraphDatabase")
    def test_related_names_returned(self, mock_gdb):
        mock_drv, mock_sess = _make_driver([_rec(name="b.uz"), _rec(name="c.uz")])
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        result = ga.find_related("a.uz")
        assert "b.uz" in result
        assert "c.uz" in result

    @patch("app.detect.graph.GraphDatabase")
    def test_empty_for_unknown_node(self, mock_gdb):
        mock_drv, mock_sess = _make_driver([])
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        result = ga.find_related("unknown.uz")
        assert result == []

    @patch("app.detect.graph.GraphDatabase")
    def test_depth_passed_to_query(self, mock_gdb):
        mock_drv, mock_sess = _make_driver([])
        mock_gdb.driver.return_value = mock_drv

        ga = GraphAnalyser()
        ga.find_related("a.uz", depth=3)

        kwargs = mock_sess.run.call_args[1]
        assert kwargs.get("depth") == 3


# ================================================================= get_campaign_id

class TestGetCampaignId:
    def test_returns_int_for_known_node(self):
        ga = GraphAnalyser()
        g = nx.Graph()
        g.add_edges_from([("a.uz", "b.uz"), ("b.uz", "c.uz")])
        with patch.object(ga, "build_nx_graph", return_value=g):
            result = ga.get_campaign_id("a.uz")
        assert isinstance(result, int)

    def test_returns_none_for_unknown_node(self):
        ga = GraphAnalyser()
        g = nx.Graph()
        g.add_node("a.uz")
        with patch.object(ga, "build_nx_graph", return_value=g):
            result = ga.get_campaign_id("unknown.uz")
        assert result is None

    def test_returns_none_on_error(self):
        ga = GraphAnalyser()
        with patch.object(ga, "build_nx_graph", side_effect=RuntimeError("ulanib bo'lmadi")):
            result = ga.get_campaign_id("a.uz")
        assert result is None

    def test_same_cluster_same_campaign_id(self):
        ga = GraphAnalyser()
        g = nx.Graph()
        g.add_edges_from([("a.uz", "b.uz"), ("b.uz", "c.uz"), ("a.uz", "c.uz")])
        with patch.object(ga, "build_nx_graph", return_value=g):
            id_a = ga.get_campaign_id("a.uz")
            id_b = ga.get_campaign_id("b.uz")
        assert id_a == id_b


# ================================================================= stats

class TestStats:
    def test_returns_dict_with_required_keys(self):
        ga = GraphAnalyser()
        g = nx.Graph()
        g.add_edges_from([("a.uz", "b.uz")])
        with patch.object(ga, "build_nx_graph", return_value=g):
            s = ga.stats()
        assert "node_count" in s
        assert "edge_count" in s
        assert "community_count" in s

    def test_node_and_edge_count(self):
        ga = GraphAnalyser()
        g = nx.Graph()
        g.add_edges_from([("a.uz", "b.uz"), ("b.uz", "c.uz")])
        with patch.object(ga, "build_nx_graph", return_value=g):
            s = ga.stats()
        assert s["node_count"] == 3
        assert s["edge_count"] == 2

    def test_community_count(self):
        ga = GraphAnalyser()
        g = nx.Graph()
        # 2 ta alohida komponent
        g.add_edge("a.uz", "b.uz")
        g.add_edge("x.uz", "y.uz")
        with patch.object(ga, "build_nx_graph", return_value=g):
            s = ga.stats()
        assert s["community_count"] >= 2

    def test_zero_stats_on_error(self):
        ga = GraphAnalyser()
        with patch.object(ga, "build_nx_graph", side_effect=Exception("xato")):
            s = ga.stats()
        assert s["node_count"] == 0
        assert s["edge_count"] == 0
        assert s["community_count"] == 0

    def test_empty_graph_zero_nodes(self):
        ga = GraphAnalyser()
        with patch.object(ga, "build_nx_graph", return_value=nx.Graph()):
            s = ga.stats()
        assert s["node_count"] == 0
        assert s["community_count"] == 0


# ================================================================= async metodlar

class TestAsyncMethods:
    def test_async_upsert_domain_calls_sync(self):
        ga = GraphAnalyser()
        with patch.object(ga, "upsert_domain") as mock_sync:
            _run(ga.async_upsert_domain("phish.uz", risk_score=70))
        mock_sync.assert_called_once_with("phish.uz", 70, None)

    def test_async_upsert_ip_calls_sync(self):
        ga = GraphAnalyser()
        with patch.object(ga, "upsert_ip") as mock_sync:
            _run(ga.async_upsert_ip("1.2.3.4", asn="AS123"))
        mock_sync.assert_called_once_with("1.2.3.4", "AS123", None)

    def test_async_stats_calls_sync(self):
        ga = GraphAnalyser()
        expected = {"node_count": 5, "edge_count": 4, "community_count": 2}
        with patch.object(ga, "stats", return_value=expected):
            result = _run(ga.async_stats())
        assert result == expected

    def test_async_build_nx_graph_returns_graph(self):
        ga = GraphAnalyser()
        g = nx.Graph()
        g.add_node("a.uz")
        with patch.object(ga, "build_nx_graph", return_value=g):
            result = _run(ga.async_build_nx_graph())
        assert isinstance(result, nx.Graph)
        assert "a.uz" in result.nodes
