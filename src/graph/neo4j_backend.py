from typing import Any, Dict, List, Optional

from src.config import get_settings
from src.utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

try:
    from neo4j import AsyncGraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    AsyncGraphDatabase = None


class Neo4jGraphStore:
    _instance: Optional["Neo4jGraphStore"] = None

    def __init__(self, driver):
        self._driver = driver
        self._initialized = False

    @classmethod
    async def create(
        cls,
        uri: str = None,
        user: str = None,
        password: str = None,
    ) -> "Neo4jGraphStore":
        if cls._instance is not None:
            return cls._instance

        if not HAS_NEO4J:
            raise ImportError("neo4j driver not installed")

        uri = uri or settings.neo4j_uri
        user = user or settings.neo4j_user
        password = password or settings.neo4j_password

        driver = AsyncGraphDatabase.driver(
            uri,
            auth=(user, password),
            max_connection_pool_size=settings.neo4j_max_pool_size,
            connection_timeout=settings.neo4j_connection_timeout,
        )

        instance = cls(driver)
        await instance._initialize_schema()
        cls._instance = instance
        return instance

    @classmethod
    def get_instance(cls) -> Optional["Neo4jGraphStore"]:
        return cls._instance

    async def _initialize_schema(self):
        if self._initialized:
            return
        async with self._driver.session() as session:
            await session.run(
                "CREATE CONSTRAINT entity_key IF NOT EXISTS "
                "FOR (e:Entity) REQUIRE e.key IS UNIQUE"
            )
            await session.run(
                "CREATE INDEX entity_type_idx IF NOT EXISTS "
                "FOR (e:Entity) ON (e.type)"
            )
            await session.run(
                "CREATE CONSTRAINT session_id IF NOT EXISTS "
                "FOR (s:Session) REQUIRE s.id IS UNIQUE"
            )
        self._initialized = True

    async def add_entities(
        self,
        session_id: str,
        entities: List[Dict[str, str]],
    ) -> int:
        if not entities:
            return 0

        query = """
        UNWIND $entities AS ent
        MERGE (e:Entity {key: ent.key})
        ON CREATE SET e.type = ent.type, e.value = ent.value,
                      e.weight = ent.weight, e.first_seen = datetime()
        ON MATCH SET e.last_seen = datetime()
        WITH e, ent
        MERGE (s:Session {id: $session_id})
        MERGE (s)-[:CONTAINS]->(e)
        RETURN count(e) AS cnt
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    query, session_id=session_id, entities=entities
                )
                record = await result.single()
                return record["cnt"] if record else 0
        except Exception as e:
            logger.error(f"Neo4j add_entities failed: {e}")
            return 0

    async def link_entities(
        self,
        pairs: List[Dict[str, str]],
    ) -> None:
        if not pairs:
            return

        query = """
        UNWIND $pairs AS pair
        MATCH (e1:Entity {key: pair.key1}), (e2:Entity {key: pair.key2})
        MERGE (e1)-[r:CO_OCCURS]-(e2)
        ON CREATE SET r.weight = 1, r.sessions = [pair.session_id]
        ON MATCH SET r.weight = r.weight + 1,
                     r.sessions = CASE
                         WHEN NOT pair.session_id IN r.sessions
                         THEN r.sessions + pair.session_id
                         ELSE r.sessions
                     END
        """
        try:
            async with self._driver.session() as session:
                await session.run(query, pairs=pairs)
        except Exception as e:
            logger.error(f"Neo4j link_entities failed: {e}")

    async def detect_fraud_rings(
        self, min_size: int = 3, limit: int = 100
    ) -> List[Dict[str, Any]]:
        query = """
        MATCH (e:Entity)
        WITH collect(e) AS all_entities
        UNWIND all_entities AS seed
        MATCH path = (seed)-[:CO_OCCURS*0..]-(connected:Entity)
        WITH seed, collect(DISTINCT connected) AS component
        WITH component, component[0].key AS canonical
        WHERE size(component) >= $min_size
        WITH canonical, component
        ORDER BY size(component) DESC
        LIMIT $limit
        UNWIND component AS member
        WITH canonical, collect(DISTINCT {
            key: member.key,
            type: member.type,
            value: member.value
        }) AS entities
        OPTIONAL MATCH (s:Session)-[:CONTAINS]->(e:Entity)
        WHERE e.key IN [ent IN entities | ent.key]
        WITH canonical, entities, collect(DISTINCT s.id) AS sessions
        RETURN canonical AS ring_id,
               entities,
               sessions,
               size(entities) AS size
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    query, min_size=min_size, limit=limit
                )
                rings = []
                seen_canonicals = set()
                async for record in result:
                    cid = record["ring_id"]
                    if cid in seen_canonicals:
                        continue
                    seen_canonicals.add(cid)
                    rings.append({
                        "ring_id": cid,
                        "entities": record["entities"],
                        "sessions": record["sessions"],
                        "size": record["size"],
                    })
                return rings
        except Exception as e:
            logger.error(f"Neo4j detect_fraud_rings failed: {e}")
            return []

    async def identify_kingpins(self, top_n: int = 10) -> List[Dict[str, Any]]:
        query = """
        MATCH (e:Entity)
        OPTIONAL MATCH (e)-[r:CO_OCCURS]-(other:Entity)
        OPTIONAL MATCH (s:Session)-[:CONTAINS]->(e)
        WITH e,
             count(DISTINCT other) AS degree,
             count(DISTINCT s) AS session_count,
             count(DISTINCT r) AS edge_count
        ORDER BY degree DESC, session_count DESC
        LIMIT $top_n
        RETURN e.key AS key,
               e.type AS type,
               e.value AS value,
               degree,
               session_count,
               edge_count
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(query, top_n=top_n)
                kingpins = []
                async for record in result:
                    kingpins.append({
                        "entity_key": record["key"],
                        "entity_type": record["type"],
                        "entity_value": record["value"],
                        "degree": record["degree"],
                        "connected_sessions": record["session_count"],
                        "connected_entities": record["degree"],
                    })
                return kingpins
        except Exception as e:
            logger.error(f"Neo4j identify_kingpins failed: {e}")
            return []

    async def get_statistics(self) -> Dict[str, Any]:
        query = """
        OPTIONAL MATCH (e:Entity)
        WITH count(e) AS total_entities
        OPTIONAL MATCH ()-[r:CO_OCCURS]-()
        WITH total_entities, count(r) / 2 AS total_edges
        OPTIONAL MATCH (s:Session)
        WITH total_entities, total_edges, count(s) AS total_sessions
        OPTIONAL MATCH (e:Entity)
        WITH total_entities, total_edges, total_sessions,
             e.type AS etype, count(e) AS type_count
        RETURN total_entities, total_edges, total_sessions,
               collect({type: etype, count: type_count}) AS type_breakdown
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(query)
                record = await result.single()
                if not record:
                    return {}
                type_map = {}
                for tb in record["type_breakdown"]:
                    if tb["type"]:
                        type_map[tb["type"]] = tb["count"]
                return {
                    "total_entities": record["total_entities"],
                    "total_edges": record["total_edges"],
                    "total_sessions": record["total_sessions"],
                    "entity_types": type_map,
                }
        except Exception as e:
            logger.error(f"Neo4j get_statistics failed: {e}")
            return {}

    async def load_to_networkx(self):
        try:
            import networkx as nx
        except ImportError:
            return None

        entities_query = """
        MATCH (e:Entity)
        RETURN e.key AS key, e.type AS type, e.value AS value, e.weight AS weight
        """
        edges_query = """
        MATCH (e1:Entity)-[r:CO_OCCURS]-(e2:Entity)
        WHERE id(e1) < id(e2)
        RETURN e1.key AS key1, e2.key AS key2,
               r.weight AS weight, r.sessions AS sessions
        """
        sessions_query = """
        MATCH (s:Session)-[:CONTAINS]->(e:Entity)
        RETURN s.id AS session_id, collect(e.key) AS entity_keys
        """
        graph = nx.Graph()
        entity_types = {}
        entity_sessions = {}
        session_entities = {}

        try:
            async with self._driver.session() as session:
                result = await session.run(entities_query)
                async for record in result:
                    key = record["key"]
                    graph.add_node(
                        key,
                        entity_type=record["type"],
                        value=record["value"],
                        weight=record["weight"] or 0.5,
                    )
                    entity_types[key] = record["type"]

                result = await session.run(edges_query)
                async for record in result:
                    sessions_list = record["sessions"] or []
                    graph.add_edge(
                        record["key1"],
                        record["key2"],
                        weight=record["weight"] or 1,
                        sessions=set(sessions_list),
                    )

                result = await session.run(sessions_query)
                async for record in result:
                    sid = record["session_id"]
                    keys = record["entity_keys"]
                    session_entities[sid] = set(keys)
                    for k in keys:
                        if k not in entity_sessions:
                            entity_sessions[k] = set()
                        entity_sessions[k].add(sid)

            return {
                "graph": graph,
                "entity_types": entity_types,
                "entity_sessions": entity_sessions,
                "session_entities": session_entities,
            }
        except Exception as e:
            logger.error(f"Neo4j load_to_networkx failed: {e}")
            return None

    async def health_check(self) -> bool:
        try:
            async with self._driver.session() as session:
                result = await session.run("RETURN 1 AS ok")
                record = await result.single()
                return record is not None and record["ok"] == 1
        except Exception:
            return False

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()
        Neo4jGraphStore._instance = None
