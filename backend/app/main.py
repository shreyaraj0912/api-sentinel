from fastapi import FastAPI

from .database import Base, engine
from .routes.events import router as events_router
from .routes.inventory import router as inventory_router


# Create database tables if they do not already exist.
Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="API-Sentinel Backend",
    description=(
        "Backend telemetry ingestion and API security "
        "monitoring service"
    ),
    version="0.1.0",
)


@app.get("/")
def root():
    """
    Basic application information.
    """

    return {
        "message": "API-Sentinel Backend Running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    """
    Health check endpoint.
    """

    return {
        "status": "ok"
    }


# Register API routers.
app.include_router(events_router)
app.include_router(inventory_router)