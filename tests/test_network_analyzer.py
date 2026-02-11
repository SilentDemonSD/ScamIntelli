import pytest

from src.intelligence_extractor.network_analyzer import (
    ScammerNetworkAnalyzer,
    get_network_analyzer,
)
from src.models import ExtractedIntelligence


@pytest.fixture
def analyzer():
    a = ScammerNetworkAnalyzer()
    return a


@pytest.fixture
def sample_intel_1():
    return ExtractedIntelligence(
        bank_accounts=["1234567890"],
        upi_ids=["scammer@upi"],
        phishing_links=["https://fake-bank.com"],
        phone_numbers=["9876543210"],
        suspicious_keywords=["otp", "verify"],
    )


@pytest.fixture
def sample_intel_2():
    return ExtractedIntelligence(
        bank_accounts=["1234567890"],
        upi_ids=["scammer@upi", "other@paytm"],
        phishing_links=[],
        phone_numbers=["9876543210", "8765432109"],
        suspicious_keywords=["transfer"],
    )


@pytest.fixture
def sample_intel_3():
    return ExtractedIntelligence(
        bank_accounts=["0987654321"],
        upi_ids=["other@paytm"],
        phishing_links=["https://phish.com"],
        phone_numbers=["8765432109"],
        suspicious_keywords=["urgent"],
    )


def test_add_intelligence(analyzer, sample_intel_1):
    added = analyzer.add_intelligence("session-1", sample_intel_1)
    assert added == 4
    stats = analyzer.get_network_statistics()
    assert stats.total_entities == 4
    assert stats.total_sessions_tracked == 1


def test_duplicate_entities_not_readded(analyzer, sample_intel_1):
    analyzer.add_intelligence("session-1", sample_intel_1)
    added = analyzer.add_intelligence("session-2", sample_intel_1)
    assert added == 0
    stats = analyzer.get_network_statistics()
    assert stats.total_entities == 4
    assert stats.total_sessions_tracked == 2


def test_detect_fraud_rings(analyzer, sample_intel_1, sample_intel_2, sample_intel_3):
    analyzer.add_intelligence("session-1", sample_intel_1)
    analyzer.add_intelligence("session-2", sample_intel_2)
    analyzer.add_intelligence("session-3", sample_intel_3)

    rings = analyzer.detect_fraud_rings()
    assert len(rings) >= 1
    largest_ring = rings[0]
    assert largest_ring.size >= 3
    assert len(largest_ring.sessions) >= 2
    assert largest_ring.risk_score > 0


def test_identify_kingpins(analyzer, sample_intel_1, sample_intel_2, sample_intel_3):
    analyzer.add_intelligence("session-1", sample_intel_1)
    analyzer.add_intelligence("session-2", sample_intel_2)
    analyzer.add_intelligence("session-3", sample_intel_3)

    kingpins = analyzer.identify_kingpins(top_n=5)
    assert len(kingpins) > 0
    top = kingpins[0]
    assert top.centrality_score > 0
    assert top.connected_sessions >= 1
    assert top.entity_type in ("upi_id", "bank_account", "phone_number", "phishing_link")


def test_get_session_connections(analyzer, sample_intel_1, sample_intel_2):
    analyzer.add_intelligence("session-1", sample_intel_1)
    analyzer.add_intelligence("session-2", sample_intel_2)

    connections = analyzer.get_session_connections("session-1")
    assert connections["session_id"] == "session-1"
    assert "session-2" in connections["connected_sessions"]
    assert connections["risk_level"] in ("low", "medium", "high", "critical")


def test_empty_session_connections(analyzer):
    connections = analyzer.get_session_connections("nonexistent")
    assert connections["entities"] == []
    assert connections["connected_sessions"] == []
    assert connections["risk_level"] == "none"


def test_network_statistics_empty(analyzer):
    stats = analyzer.get_network_statistics()
    assert stats.total_entities == 0
    assert stats.total_edges == 0
    assert stats.fraud_rings_detected == 0
    assert stats.network_density == 0.0


def test_network_statistics_populated(analyzer, sample_intel_1, sample_intel_2, sample_intel_3):
    analyzer.add_intelligence("s1", sample_intel_1)
    analyzer.add_intelligence("s2", sample_intel_2)
    analyzer.add_intelligence("s3", sample_intel_3)

    stats = analyzer.get_network_statistics()
    assert stats.total_entities > 0
    assert stats.total_edges > 0
    assert stats.total_sessions_tracked == 3
    assert stats.connected_components >= 1


def test_reset(analyzer, sample_intel_1):
    analyzer.add_intelligence("s1", sample_intel_1)
    assert analyzer.get_network_statistics().total_entities > 0
    analyzer.reset()
    assert analyzer.get_network_statistics().total_entities == 0


def test_global_analyzer_singleton():
    a1 = get_network_analyzer()
    a2 = get_network_analyzer()
    assert a1 is a2


def test_no_fraud_rings_below_threshold(analyzer):
    intel = ExtractedIntelligence(
        bank_accounts=["acc1"],
        upi_ids=[],
        phishing_links=[],
        phone_numbers=[],
        suspicious_keywords=[],
    )
    analyzer.add_intelligence("s1", intel)
    rings = analyzer.detect_fraud_rings()
    assert len(rings) == 0


def test_empty_intelligence(analyzer):
    intel = ExtractedIntelligence()
    added = analyzer.add_intelligence("s1", intel)
    assert added == 0
    assert analyzer.get_network_statistics().total_entities == 0
