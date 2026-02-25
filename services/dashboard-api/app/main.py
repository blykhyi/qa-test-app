from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
from .routes import findings, stats, vulnerabilities, health

app = FastAPI(title="Vulnerability Dashboard API", version="1.0.0")

app.include_router(health.router)
app.include_router(findings.router)
app.include_router(stats.router)
app.include_router(vulnerabilities.router)

# Serve static UI files
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
def serve_ui():
    return FileResponse(str(static_dir / "index.html"))
