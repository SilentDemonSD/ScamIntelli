import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from src.models import ExtractedIntelligence
from src.utils.logging import get_logger

logger = get_logger(__name__)

try:
    import networkx as nx

    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = None

ENTITY_WEIGHTS: Dict[str, float] = {
    "upi_id": 0.9,
    "bank_account": 0.95,
    "phone_number": 0.8,
    "phishing_link": 0.85,
}

KINGPIN_CENTRALITY_WEIGHTS: Dict[str, float] = {
    "degree": 0.4,
    "betweenness": 0.4,
    "eigenvector": 0.2,
}

MIN_RING_SIZE = 3
MAX_RING_ANALYSIS = 100


@dataclass
class FraudRing:
    ring_id: str
    entities: List[Dict[str, str]]
    sessions: List[str]
    risk_score: float
    size: int
    entity_types: Dict[str, int]
    first_seen: str
    last_seen: str


@dataclass
class KingpinEntity:
    entity_value: str
    entity_type: str
    centrality_score: float
    connected_sessions: int
    connected_entities: int
    degree_centrality: float
    betweenness_centrality: float
    eigenvector_centrality: float


@dataclass
class NetworkStatistics:
    total_entities: int
    total_edges: int
    total_sessions_tracked: int
    connected_components: int
    fraud_rings_detected: int
    average_cluster_coefficient: float
    network_density: float
    top_entity_types: Dict[str, int]


class ScammerNetworkAnalyzer:

    def __init__(self) -> None:
        self._entity_sessions: Dict[str, Set[str]] = defaultdict(set)
        self._session_entities: Dict[str, Set[str]] = defaultdict(set)
        self._entity_types: Dict[str, str] = {}
        self._entity_timestamps: Dict[str, List[str]] = defaultdict(list)
        self._graph: Optional[Any] = None
        self._dirty = True

        if HAS_NETWORKX:
            self._graph = nx.Graph()

    def add_intelligence(
        self, session_id: str, intel: ExtractedIntelligence
    ) -> int:
        if not HAS_NETWORKX:
            return 0

        entities_added = 0
        now = datetime.now(timezone.utc).isoformat()

        entity_map = {
            "upi_id": intel.upi_ids,
            "bank_account": intel.bank_accounts,
            "phone_number": intel.phone_numbers,
            "phishing_link": intel.phishing_links,
        }

        session_entities: List[str] = []

        for entity_type, values in entity_map.items():
            for value in values:
                entity_key = f"{entity_type}:{value}"
                self._entity_sessions[entity_key].add(session_id)
                self._session_entities[session_id].add(entity_key)
                self._entity_types[entity_key] = entity_type
                self._entity_timestamps[entity_key].append(now)
                session_entities.append(entity_key)

                if not self._graph.has_node(entity_key):
                    self._graph.add_node(
                        entity_key,
                        entity_type=entity_type,
                        value=value,
                        weight=ENTITY_WEIGHTS.get(entity_type, 0.5),
                    )
                    entities_added += 1

        for i in range(len(session_entities)):
            for j in range(i + 1, len(session_entities)):
                e1, e2 = session_entities[i], session_entities[j]
                if self._graph.has_edge(e1, e2):
                    self._graph[e1][e2]["weight"] += 1
                    self._graph[e1][e2]["sessions"].add(session_id)
                else:
                    self._graph.add_edge(
                        e1, e2, weight=1, sessions={session_id}
                    )

        self._dirty = True
        return entities_added

    def detect_fraud_rings(self) -> List[FraudRing]:
        if not HAS_NETWORKX or self._graph is None:
            return []

        if self._graph.number_of_nodes() < MIN_RING_SIZE:
            return []

        rings = []
        components = list(nx.connected_components(self._graph))

        for component in components[:MAX_RING_ANALYSIS]:
            if len(component) < MIN_RING_SIZE:
                continue

            entities = []
            sessions: Set[str] = set()
            entity_type_counts: Dict[str, int] = defaultdict(int)
            timestamps: List[str] = []

            for entity_key in component:
                etype = self._entity_types.get(entity_key, "unknown")
                value = entity_key.split(":", 1)[1] if ":" in entity_key else entity_key
                entities.append({"type": etype, "value": value})
                entity_type_counts[etype] += 1
                sessions.update(self._entity_sessions.get(entity_key, set()))
                timestamps.extend(
                    self._entity_timestamps.get(entity_key, [])
                )

            sorted_timestamps = sorted(timestamps) if timestamps else []
            risk_score = self._calculate_ring_risk(
                component, sessions, entity_type_counts
            )

            ring_id = hashlib.sha256(
                "|".join(sorted(component)).encode()
            ).hexdigest()[:16]

            rings.append(
                FraudRing(
                    ring_id=ring_id,
                    entities=entities,
                    sessions=sorted(sessions),
                    risk_score=round(risk_score, 4),
                    size=len(component),
                    entity_types=dict(entity_type_counts),
                    first_seen=sorted_timestamps[0] if sorted_timestamps else "",
                    last_seen=sorted_timestamps[-1] if sorted_timestamps else "",
                )
            )

        return sorted(rings, key=lambda r: r.risk_score, reverse=True)

    def identify_kingpins(self, top_n: int = 10) -> List[KingpinEntity]:
        if not HAS_NETWORKX or self._graph is None:
            return []

        if self._graph.number_of_nodes() < 2:
            return []

        try:
            degree_cent = nx.degree_centrality(self._graph)
            betweenness_cent = nx.betweenness_centrality(self._graph)

            try:
                eigenvector_cent = nx.eigenvector_centrality(
                    self._graph, max_iter=1000, tol=1e-6
                )
            except nx.PowerIterationFailedConvergence:
                eigenvector_cent = {n: 0.0 for n in self._graph.nodes()}
        except Exception as e:
            logger.warning(f"Centrality calculation failed: {e}")
            return []

        kingpins = []
        for node in self._graph.nodes():
            d = degree_cent.get(node, 0.0)
            b = betweenness_cent.get(node, 0.0)
            e = eigenvector_cent.get(node, 0.0)

            composite = (
                d * KINGPIN_CENTRALITY_WEIGHTS["degree"]
                + b * KINGPIN_CENTRALITY_WEIGHTS["betweenness"]
                + e * KINGPIN_CENTRALITY_WEIGHTS["eigenvector"]
            )

            etype = self._entity_types.get(node, "unknown")
            value = node.split(":", 1)[1] if ":" in node else node

            kingpins.append(
                KingpinEntity(
                    entity_value=value,
                    entity_type=etype,
                    centrality_score=round(composite, 6),
                    connected_sessions=len(self._entity_sessions.get(node, set())),
                    connected_entities=self._graph.degree(node),
                    degree_centrality=round(d, 6),
                    betweenness_centrality=round(b, 6),
                    eigenvector_centrality=round(e, 6),
                )
            )

        kingpins.sort(key=lambda k: k.centrality_score, reverse=True)
        return kingpins[:top_n]

    def get_network_statistics(self) -> NetworkStatistics:
        if not HAS_NETWORKX or self._graph is None:
            return NetworkStatistics(
                total_entities=0,
                total_edges=0,
                total_sessions_tracked=0,
                connected_components=0,
                fraud_rings_detected=0,
                average_cluster_coefficient=0.0,
                network_density=0.0,
                top_entity_types={},
            )

        entity_type_counts: Dict[str, int] = defaultdict(int)
        for etype in self._entity_types.values():
            entity_type_counts[etype] += 1

        components = list(nx.connected_components(self._graph))
        fraud_ring_count = sum(1 for c in components if len(c) >= MIN_RING_SIZE)

        try:
            avg_clustering = nx.average_clustering(self._graph)
        except Exception:
            avg_clustering = 0.0

        return NetworkStatistics(
            total_entities=self._graph.number_of_nodes(),
            total_edges=self._graph.number_of_edges(),
            total_sessions_tracked=len(self._session_entities),
            connected_components=len(components),
            fraud_rings_detected=fraud_ring_count,
            average_cluster_coefficient=round(avg_clustering, 6),
            network_density=round(nx.density(self._graph), 6),
            top_entity_types=dict(entity_type_counts),
        )

    def get_session_connections(self, session_id: str) -> Dict[str, Any]:
        entities = self._session_entities.get(session_id, set())
        if not entities:
            return {
                "session_id": session_id,
                "entities": [],
                "connected_sessions": [],
                "risk_level": "none",
            }

        connected_sessions: Set[str] = set()
        entity_details = []

        for entity_key in entities:
            for other_session in self._entity_sessions.get(entity_key, set()):
                if other_session != session_id:
                    connected_sessions.add(other_session)

            etype = self._entity_types.get(entity_key, "unknown")
            value = entity_key.split(":", 1)[1] if ":" in entity_key else entity_key
            entity_details.append({"type": etype, "value": value})

        risk_level = "low"
        if len(connected_sessions) >= 5:
            risk_level = "critical"
        elif len(connected_sessions) >= 3:
            risk_level = "high"
        elif len(connected_sessions) >= 1:
            risk_level = "medium"

        return {
            "session_id": session_id,
            "entities": entity_details,
            "connected_sessions": sorted(connected_sessions),
            "risk_level": risk_level,
        }

    def _calculate_ring_risk(
        self,
        component: Set[str],
        sessions: Set[str],
        entity_types: Dict[str, int],
    ) -> float:
        size_factor = min(len(component) / 20.0, 1.0) * 0.3
        session_factor = min(len(sessions) / 10.0, 1.0) * 0.3

        type_diversity = len(entity_types) / max(len(ENTITY_WEIGHTS), 1)
        diversity_factor = min(type_diversity, 1.0) * 0.2

        high_value_count = sum(
            count
            for etype, count in entity_types.items()
            if ENTITY_WEIGHTS.get(etype, 0) >= 0.9
        )
        value_factor = min(high_value_count / max(len(component), 1), 1.0) * 0.2

        return size_factor + session_factor + diversity_factor + value_factor

    def reset(self) -> None:
        self._entity_sessions.clear()
        self._session_entities.clear()
        self._entity_types.clear()
        self._entity_timestamps.clear()
        if HAS_NETWORKX:
            self._graph = nx.Graph()
        self._dirty = True


_global_analyzer: Optional[ScammerNetworkAnalyzer] = None


def get_network_analyzer() -> ScammerNetworkAnalyzer:
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = ScammerNetworkAnalyzer()
    return _global_analyzer
