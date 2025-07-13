# app/main.py
from fastapi import FastAPI
from .router import router

app = FastAPI(title="Web Vulnerability Scanner")

app.include_router(router)