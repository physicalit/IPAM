import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import OperationalError
import time
import logging

logger = logging.getLogger("ipam.db")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO").upper()))

# Load environment variables from a local .env file if present
load_dotenv(dotenv_path=os.environ.get("ENV_FILE", ".env"), override=False)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./ipam.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False, "timeout": 30}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        # Improve concurrency on SQLite
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=30000;")
        cursor.close()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def commit_with_retry(db, attempts: int = 6, sleep: float = 0.2):
    """Commit with simple exponential backoff on SQLite lock."""
    for i in range(attempts):
        try:
            db.commit()
            return True
        except OperationalError as e:
            if "database is locked" in str(e):
                time.sleep(sleep * (2 ** i))
                continue
            raise
    try:
        db.rollback()
    except Exception:
        logger.exception("commit_with_retry: rollback failed after OperationalError")
    return False
