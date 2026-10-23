"""
PhishGuard AI — FastAPI Main Application
Entry point for the backend server.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import APP_TITLE, APP_VERSION, APP_DESCRIPTION, CORS_ORIGINS, CORS_ORIGIN_REGEX
from backend.app.api.routes import router
from backend.app.database.db import initialize_database
from backend.app.ml.predictor import predictor


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # --- Startup ---
    print(f"\n{'='*60}")
    print(f"  {APP_TITLE} v{APP_VERSION}")
    print(f"  {APP_DESCRIPTION}")
    print(f"{'='*60}\n")

    # Initialize database
    print("[STARTUP] Initializing database...")
    initialize_database()

    # Load ML models
    print("[STARTUP] Loading ML models...")
    predictor.load_models()

    model_status = predictor.get_status()
    if not model_status["url_model_loaded"] or not model_status["message_model_loaded"]:
        print("\n[STARTUP] WARNING: Some ML models are not loaded.")
        print("[STARTUP] Run: python -m backend.app.ml.train")
        print("[STARTUP] The system will use rule-based fallback until models are trained.\n")

    print(f"\n[STARTUP] Server ready at http://localhost:8000")
    print(f"[STARTUP] API docs at http://localhost:8000/docs\n")

    yield

    # --- Shutdown ---
    print("\n[SHUTDOWN] PhishGuard AI shutting down.")


# Create FastAPI application
app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api")
