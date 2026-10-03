import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.config import settings

# If running unit tests or offline, allow sqlite+aiosqlite memory database
db_url = settings.get_database_url
if os.getenv("TESTING") == "1" or "sqlite" in db_url:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
else:
    try:
        engine = create_async_engine(db_url, echo=False, pool_pre_ping=True)
    except Exception:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)



async_session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()
