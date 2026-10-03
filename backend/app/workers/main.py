import asyncio
import structlog
from app.config import settings
from app.workers.expiry_kicker import run_expiry_kicker_loop
from app.workers.rotation_watcher import run_rotation_watcher_loop

logger = structlog.get_logger(__name__)

async def main():
    logger.info("=== AuthSphere Bridge Workers Starting ===", env=settings.ENV)
    
    tasks = [
        asyncio.create_task(run_expiry_kicker_loop(15)),
        asyncio.create_task(run_rotation_watcher_loop(15)),
    ]

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
