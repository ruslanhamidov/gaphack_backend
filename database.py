import os
from sqlmodel import create_engine, Session, SQLModel

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./gaphack.db")
# Render gives postgres:// but SQLAlchemy needs postgresql://
DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)

def get_session():
    with Session(engine) as session:
        yield session

def init_db():
    SQLModel.metadata.create_all(engine)