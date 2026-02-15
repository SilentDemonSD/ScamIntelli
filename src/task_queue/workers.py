import asyncio
import signal
import uuid
from typing import Any, Callable, Dict

from src.config import get_settings
from src.task_queue.broker import TaskBroker, TaskMessage, get_or_create_broker
from src.utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class TaskWorker:
    def __init__(
        self,
        broker: TaskBroker,
        consumer_name: str = None,
        concurrency: int = None,
    ):
        self._broker = broker
        self._consumer_name = consumer_name or f"worker-{uuid.uuid4().hex[:8]}"
        self._concurrency = concurrency or settings.worker_concurrency
        self._handlers: Dict[str, Callable] = {}
        self._running = False
        self._semaphore = asyncio.Semaphore(self._concurrency)
        self._tasks: set = set()

    def register_handler(self, task_type: str, handler: Callable) -> None:
        self._handlers[task_type] = handler

    async def start(self) -> None:
        self._running = True
        logger.info(
            f"Worker {self._consumer_name} starting "
            f"(concurrency={self._concurrency})"
        )

        reclaim_task = asyncio.create_task(self._reclaim_loop())
        self._tasks.add(reclaim_task)
        reclaim_task.add_done_callback(self._tasks.discard)

        while self._running:
            try:
                entries = await self._broker.consume(
                    self._consumer_name,
                    count=self._concurrency,
                    block_ms=2000,
                )

                for msg_id, task in entries:
                    await self._semaphore.acquire()
                    t = asyncio.create_task(self._process_task(msg_id, task))
                    self._tasks.add(t)
                    t.add_done_callback(lambda _t: (self._semaphore.release(), self._tasks.discard(_t)))

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
                await asyncio.sleep(1)

        await self._drain()
        reclaim_task.cancel()
        logger.info(f"Worker {self._consumer_name} stopped")

    async def stop(self) -> None:
        self._running = False

    async def _drain(self) -> None:
        if self._tasks:
            logger.info(f"Draining {len(self._tasks)} in-flight tasks")
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _process_task(self, msg_id: str, task: TaskMessage) -> None:
        handler = self._handlers.get(task.task_type)
        if not handler:
            logger.warning(f"No handler for task type: {task.task_type}")
            await self._broker.acknowledge(msg_id)
            return

        try:
            result = handler(task.payload)
            if asyncio.iscoroutine(result):
                await result
            await self._broker.acknowledge(msg_id)
        except Exception as e:
            logger.error(
                f"Task {task.task_id} ({task.task_type}) failed: {e}"
            )
            await self._broker.acknowledge(msg_id)
            await self._broker.retry_or_dlq(task, str(e))

    async def _reclaim_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(30)
                reclaimed = await self._broker.reclaim_pending(
                    self._consumer_name
                )
                if reclaimed > 0:
                    logger.info(f"Reclaimed {reclaimed} abandoned tasks")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Reclaim loop error: {e}")


async def handle_callback_task(payload: Dict[str, Any]) -> None:
    from src.callback_worker.guvi_callback import send_guvi_callback
    from src.models import SessionState

    session_data = payload.get("session_data", {})
    if not session_data:
        session_id = payload.get("session_id")
        from src.session_manager.session_store import get_or_create_session_store
        store = await get_or_create_session_store()
        session = await store.get(session_id)
        if session is None:
            logger.warning(f"Session {session_id} not found for callback")
            return
    else:
        session = SessionState(**session_data)

    await send_guvi_callback(session)


async def handle_graph_update_task(payload: Dict[str, Any]) -> None:
    from src.intelligence_extractor.network_analyzer import get_network_analyzer
    from src.models import ExtractedIntelligence

    session_id = payload.get("session_id")
    intel_data = payload.get("intel", {})

    intel = ExtractedIntelligence(**intel_data)
    analyzer = get_network_analyzer()
    analyzer.add_intelligence(session_id, intel)


async def handle_fingerprint_task(payload: Dict[str, Any]) -> None:
    from src.intelligence_extractor.behavioral_fingerprint import get_fingerprinter

    session_id = payload.get("session_id")
    messages = payload.get("messages", [])

    if len(messages) < 3:
        return

    fingerprinter = get_fingerprinter()
    fp = fingerprinter.create_fingerprint(session_id, messages)
    if fp:
        fingerprinter.store_fingerprint(fp)
        fingerprinter.match_fingerprint(fp)


def create_default_worker(broker: TaskBroker) -> TaskWorker:
    worker = TaskWorker(broker)
    worker.register_handler("callback", handle_callback_task)
    worker.register_handler("graph_update", handle_graph_update_task)
    worker.register_handler("fingerprint", handle_fingerprint_task)
    return worker


async def run_worker() -> None:
    broker = await get_or_create_broker()
    if broker is None:
        logger.error("Cannot start worker: no broker available (Redis required)")
        return

    worker = create_default_worker(broker)

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.ensure_future(worker.stop()))
        except NotImplementedError:
            pass

    await worker.start()


if __name__ == "__main__":
    asyncio.run(run_worker())
