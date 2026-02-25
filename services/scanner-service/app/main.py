from fastapi import FastAPI
from .routes import assets, scans, health

app = FastAPI(title="Scanner Service", version="1.0.0")

app.include_router(health.router)
app.include_router(assets.router)
app.include_router(scans.router)
