from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base
DATABASE_URL = "sqlite:///./dev.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(bind=engine)
