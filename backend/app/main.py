from fastapi import FastAPI
from app.api.v1 import routers

app = FastAPI(title="VulnX API")
app.include_router(routers.router, prefix="/api/v1")
