from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from analytics import router as analytics_router
from attack_simulator import router as attack_simulator_router
from auth_module import router as auth_router
from backup_manager import router as backup_router
from breach_detection import router as breach_router
from login_monitor import router as login_monitor_router
from password_generator import router as password_generator_router
from password_strength import router as password_strength_router


app = FastAPI(
    title="Security Intelligence API",
    version="1.0.0",
    root_path="/api",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    swagger_ui_parameters={"persistAuthorization": True},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def health_check():
    return {"status": "ok", "message": "Security Intelligence API is running"}


app.include_router(auth_router)
app.include_router(analytics_router)
app.include_router(password_strength_router)
app.include_router(breach_router)
app.include_router(login_monitor_router)
app.include_router(password_generator_router)
app.include_router(attack_simulator_router)
app.include_router(backup_router)
