from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


# SQLite database file will be created in the project root.
DATABASE_URL = "sqlite:///./api_sentinel.db"


# SQLite normally prevents connections from being shared between threads.
# FastAPI may use multiple threads, so we disable that restriction.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


# Database session factory.
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# Base class used by SQLAlchemy models.
Base = declarative_base()


def get_db():
    """
    Provide a database session to FastAPI routes.

    The session is automatically closed after the request finishes.
    """
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()