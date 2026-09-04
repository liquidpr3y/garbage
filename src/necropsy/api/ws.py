"""Live case event stream.

Workers cannot hold WebSocket connections, so they publish to Redis and the API
process fans out. Building this in Phase 1 with one event shape is the
difference between a live sandbox timeline in Phase 3 and a polling rewrite.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from necropsy.contracts.events import case_channel
from necropsy.runtime import get_host

log = logging.getLogger(__name__)
router = APIRouter()

POLL_INTERVAL_S = 0.25


@router.websocket("/ws/cases/{case_id}")
async def case_events(websocket: WebSocket, case_id: str) -> None:
    await websocket.accept()
    channel = case_channel(case_id)

    try:
        pubsub = get_host().redis().pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(channel)
    except Exception as exc:  # noqa: BLE001
        # No broker: say so and close rather than leaving the GUI on a socket
        # that will never deliver anything.
        await websocket.send_json({"type": "stream.unavailable", "detail": str(exc)})
        await websocket.close(code=1011)
        return

    await websocket.send_json({"type": "stream.ready", "case_id": case_id})
    try:
        while True:
            # get_message is blocking, so it runs off the event loop.
            message = await asyncio.to_thread(pubsub.get_message, timeout=1.0)
            if message and message.get("type") == "message":
                data = message["data"]
                await websocket.send_text(
                    data.decode() if isinstance(data, bytes) else str(data)
                )
            await asyncio.sleep(POLL_INTERVAL_S)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        log.exception("case event stream failed for %s", case_id)
    finally:
        try:
            pubsub.close()
        except Exception:  # noqa: BLE001
            pass
