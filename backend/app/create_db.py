from db import engine
from models import Base
from app.db import get_db

print("Creating database tables...")
Base.metadata.create_all(bind=engine)
print("Done!")
