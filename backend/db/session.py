from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from core.config import settings


class Base(DeclarativeBase):
    pass


_engine = None
_session_maker = None
_db_available = False


def _setup():
    global _engine, _session_maker
    if _engine is None:
        _engine = create_async_engine(settings.DATABASE_URL, echo=False, pool_pre_ping=True)
        _session_maker = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    global _db_available
    try:
        from db.models import ScanResult, ThreatFeed  # noqa
        _setup()
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _db_available = True
        print("✅ DB tables ready")
    except Exception as e:
        print(f"⚠️  DB not available — running without persistence ({type(e).__name__})")


async def get_db():
    """Yields AsyncSession if DB is up, else None."""
    if not _db_available:
        yield None
        return
    async with _session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
