from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    role: str  # "user" or "company"
    reputation: int = 0
    bio: Optional[str] = None
    password_hash: Optional[str] = None

class Task(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    description: str
    difficulty: str
    reward_points: int
    company_id: int = Field(foreign_key="user.id")
    category: str = "Web Application"   # ← new
    tags: Optional[str] = None          # ← new, store as comma-separated e.g. "XSS,Auth"
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Submission(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(foreign_key="task.id")
    user_id: int = Field(foreign_key="user.id")
    content: str
    status: str = "pending"
    upvotes: int = 0                    # ← new
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Badge(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    task_id: Optional[int] = Field(default=None, foreign_key="task.id")
    badge_type: str
    created_at: datetime = Field(default_factory=datetime.utcnow)