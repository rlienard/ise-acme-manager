"""
ISE ACME Certificate Manager — FastAPI Application Entry Point.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .database import init_db
from .scheduler import start_scheduler, stop_scheduler
from .api import (
    settings, status, history, actions, health,
    certificates, acme_providers, dns_providers,
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info(f"Starting ISE ACME Daemon v{__version__}")
    init_db()
    start_scheduler()
    logger.info("Daemon ready")
    yield
    logger.info("Shutting down...")
    stop_scheduler()


app = FastAPI(
    title="ISE ACME Certificate Manager",
    description="API daemon for automated certificate lifecycle management on Cisco ISE",
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS — allow web interface
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health.router)
app.include_router(status.router)
app.include_router(settings.router)
app.include_router(history.router)
app.include_router(actions.router)
app.include_router(certificates.router)
app.include_router(acme_providers.router)
app.include_router(dns_providers.router)


@app.get("/")
def root():
    return {
        "name": "ISE ACME Certificate Manager",
        "version": __version__,
        "docs": "/api/docs"
    }
