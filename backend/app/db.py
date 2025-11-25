from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sqlite3
from pathlib import Path

from app.models import Base
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def init_db():
    Base.metadata.create_all(bind=engine)
