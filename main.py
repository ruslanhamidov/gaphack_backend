from typing import List

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, func, select

from database import engine, get_session, init_db
from models import Badge, Submission, Task, User


app = FastAPI(title="GapHack API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "https://gaphack-frontend.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


BADGE_REWARD_POINTS = 50


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    seed_demo_data()


def seed_demo_data() -> None:
    # Use a direct session on the shared engine for one-time seeding.
    with Session(engine) as session:
        users_exist = session.exec(select(func.count(User.id))).one()
        if users_exist:
            return

        security_researcher = User(username="security_researcher", role="user", reputation=0)
        cyber_ninja = User(username="cyber_ninja", role="user", reputation=0)
        acme_corp = User(username="acme_corp", role="company", reputation=0)

        session.add_all([security_researcher, cyber_ninja, acme_corp])
        session.commit()
        session.refresh(security_researcher)
        session.refresh(cyber_ninja)
        session.refresh(acme_corp)

        task1 = Task(
            title="Find XSS vulnerability in login form",
            description="Analyze the login page for reflected or stored XSS vectors.",
            difficulty="Medium",
            reward_points=100,
            company_id=acme_corp.id,
            category="Web Application",
            tags="XSS,Auth,Stored",
        )
        task2 = Task(
            title="Detect SQL injection in API endpoint",
            description="Review the `/api/login` endpoint for potential SQL injection.",
            difficulty="Hard",
            reward_points=150,
            company_id=acme_corp.id,
            category="Authentication",
            tags="SQLi,API,Auth",
        )

        session.add_all([task1, task2])
        session.commit()
        session.refresh(task1)
        session.refresh(task2)

        sub1 = Submission(
            task_id=task1.id,  # type: ignore[arg-type]
            user_id=security_researcher.id,  # type: ignore[arg-type]
            content="Reflected XSS in error message when invalid username is supplied.",
        )
        sub2 = Submission(
            task_id=task1.id,  # type: ignore[arg-type]
            user_id=cyber_ninja.id,  # type: ignore[arg-type]
            content="Stored XSS via profile bio field rendered on login page.",
        )
        sub3 = Submission(
            task_id=task2.id,  # type: ignore[arg-type]
            user_id=security_researcher.id,  # type: ignore[arg-type]
            content="Boolean-based blind SQL injection in `user` parameter.",
        )

        session.add_all([sub1, sub2, sub3])
        session.commit()


# -------- User endpoints --------


@app.post("/users", response_model=User)
def create_user(user: User, session: Session = Depends(get_session)) -> User:
    db_user = User(username=user.username, role=user.role, reputation=0)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@app.get("/users/{user_id}")
def get_user_profile(user_id: int, session: Session = Depends(get_session)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    badges = session.exec(select(Badge).where(Badge.user_id == user_id)).all()
    submissions = session.exec(select(Submission).where(Submission.user_id == user_id)).all()

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "reputation": user.reputation,
        "badges": badges,
        "submissions": submissions,
    }


# -------- Task endpoints --------


@app.get("/tasks")
def list_tasks(session: Session = Depends(get_session)) -> List[dict]:
    tasks = session.exec(select(Task)).all()
    return [
        {
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "difficulty": t.difficulty,
            "reward_points": t.reward_points,
            "category": t.category,
            "tags": t.tags.split(",") if t.tags else [],
            "company_id": t.company_id,
            "company": session.get(User, t.company_id).username if t.company_id else None,
            "submission_count": session.exec(
                select(func.count(Submission.id)).where(Submission.task_id == t.id)
            ).one(),
        }
        for t in tasks
    ]
    
@app.get("/users/by-username/{username}")
def get_user_by_username(username: str, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    badges = session.exec(select(Badge).where(Badge.user_id == user.id)).all()
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "reputation": user.reputation,
        "badges": [{"name": b.badge_type, "icon": "🔍"} for b in badges],
    }

@app.post("/tasks", response_model=Task)
def create_task(task: Task, session: Session = Depends(get_session)) -> Task:
    company = session.get(User, task.company_id)
    if not company or company.role != "company":
        raise HTTPException(status_code=400, detail="company_id must belong to a company user")

    db_task = Task(
        title=task.title,
        description=task.description,
        difficulty=task.difficulty,
        reward_points=task.reward_points,
        company_id=task.company_id,
    )
    session.add(db_task)
    session.commit()
    session.refresh(db_task)
    return db_task


@app.get("/tasks/{task_id}")
def get_task(task_id: int, session: Session = Depends(get_session)):
    task = session.get(Task, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    company = session.get(User, task.company_id)
    submissions = session.exec(select(Submission).where(Submission.task_id == task_id)).all()

    def submission_with_user(sub: Submission) -> dict:
        user = session.get(User, sub.user_id)
        return {
            "id": sub.id,
            "content": sub.content,
            "status": sub.status,
            "created_at": sub.created_at,
            "user": {"id": user.id, "username": user.username} if user else None,
        }

    return {
        "id": task.id,
        "title": task.title,
        "description": task.description,
        "difficulty": task.difficulty,
        "reward_points": task.reward_points,
        "company": {"id": company.id, "username": company.username} if company else None,
        "submissions": [submission_with_user(s) for s in submissions],
    }


# -------- Submission endpoints --------


@app.post("/tasks/{task_id}/submissions", response_model=Submission)
def create_submission(
    task_id: int, submission: Submission, session: Session = Depends(get_session)
) -> Submission:
    task = session.get(Task, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    user = session.get(User, submission.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="user_id must refer to an existing user")

    db_submission = Submission(
        task_id=task_id,
        user_id=submission.user_id,
        content=submission.content,
        status="pending",
    )
    session.add(db_submission)
    session.commit()
    session.refresh(db_submission)
    return db_submission


@app.get("/tasks/{task_id}/submissions")
def list_submissions(task_id: int, session: Session = Depends(get_session)):
    submissions = session.exec(select(Submission).where(Submission.task_id == task_id)).all()
    return submissions


# -------- Reward endpoint --------


@app.post("/submissions/{submission_id}/reward")
def reward_submission(submission_id: int, session: Session = Depends(get_session)):
    submission = session.get(Submission, submission_id)
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if submission.status == "rewarded":
        raise HTTPException(status_code=400, detail="Submission already rewarded")

    user = session.get(User, submission.user_id)
    task = session.get(Task, submission.task_id)
    if not user or not task:
        raise HTTPException(status_code=400, detail="Submission references invalid user or task")

    badge = Badge(
        user_id=user.id,  # type: ignore[arg-type]
        task_id=task.id,  # type: ignore[arg-type]
        badge_type="Security Finding",
    )
    submission.status = "rewarded"
    user.reputation += BADGE_REWARD_POINTS

    session.add(badge)
    session.add(submission)
    session.add(user)
    session.commit()
    session.refresh(user)

    return {"message": "Submission rewarded", "user_reputation": user.reputation}


# -------- Leaderboard endpoint --------


@app.get("/leaderboard")
def leaderboard(session: Session = Depends(get_session)):
    users = session.exec(select(User).order_by(User.reputation.desc())).all()
    badge_counts = {
        user_id: count
        for user_id, count in session.exec(
            select(Badge.user_id, func.count(Badge.id)).group_by(Badge.user_id)
        ).all()
    }

    return [
        {
            "username": u.username,
            "reputation": u.reputation,
            "badges": badge_counts.get(u.id, 0),
        }
        for u in users
    ]
