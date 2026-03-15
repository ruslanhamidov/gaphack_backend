from typing import List

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, func, select

from database import engine, get_session, init_db
from models import Badge, Submission, Task, User
import bcrypt
import re

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


def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def seed_demo_data() -> None:
    with Session(engine) as session:
        users_exist = session.exec(select(func.count(User.id))).one()
        if users_exist:
            return

        # ── Users ──────────────────────────────────────────
        researcher1 = User(username="ghost_0x1", role="user", reputation=0, email="ghost@gaphack.io", password_hash=hash_password("demo123"))
        researcher2 = User(username="null_ptr", role="user", reputation=0, email="null@gaphack.io", password_hash=hash_password("demo123"))
        researcher3 = User(username="xor_queen", role="user", reputation=0, email="xor@gaphack.io", password_hash=hash_password("demo123"))
        researcher4 = User(username="byte_wolf", role="user", reputation=0, email="byte@gaphack.io", password_hash=hash_password("demo123"))
        researcher5 = User(username="security_researcher", role="user", reputation=0, email="researcher@gaphack.io", password_hash=hash_password("demo123"))

        company1 = User(username="acme_corp", role="company", reputation=0, email="acme@gaphack.io", password_hash=hash_password("demo123"))
        company2 = User(username="securebank_az", role="company", reputation=0, email="securebank@gaphack.io", password_hash=hash_password("demo123"))
        company3 = User(username="nexacloud", role="company", reputation=0, email="nexacloud@gaphack.io", password_hash=hash_password("demo123"))

        session.add_all([researcher1, researcher2, researcher3, researcher4, researcher5, company1, company2, company3])
        session.commit()
        for u in [researcher1, researcher2, researcher3, researcher4, researcher5, company1, company2, company3]:
            session.refresh(u)

        # ── Tasks ──────────────────────────────────────────
        tasks = [
            Task(title="Find XSS vulnerability in login form", description="Analyze the login page for reflected or stored XSS vectors. Focus on the username and error message fields. Document reproduction steps and suggest a sanitization fix.", difficulty="Medium", reward_points=300, company_id=company1.id, category="Web Application", tags="XSS,Auth,Stored"),
            Task(title="Detect SQL injection in API endpoint", description="Review the /api/login endpoint for potential SQL injection. Test boolean-based, time-based, and error-based injection techniques against all input parameters.", difficulty="Hard", reward_points=500, company_id=company1.id, category="Authentication", tags="SQLi,API,Auth"),
            Task(title="JWT Token Forgery Analysis", description="Investigate our JWT implementation for algorithm confusion attacks (HS256 vs RS256), weak secrets, and improper claim validation. Check for missing expiry checks.", difficulty="Hard", reward_points=800, company_id=company2.id, category="Authentication", tags="JWT,Crypto,Token"),
            Task(title="CSRF in Fund Transfer Flow", description="Assess the multi-step fund transfer UI for CSRF vulnerabilities. Focus on state-changing operations that lack proper token validation or SameSite cookie attributes.", difficulty="Critical", reward_points=1500, company_id=company2.id, category="Web Application", tags="CSRF,Finance,Session"),
            Task(title="AWS S3 Bucket Misconfiguration Audit", description="Review public-facing S3 bucket policies for data exposure risks, improper ACLs, and cross-account access issues. Check for publicly listable buckets and exposed credentials.", difficulty="Medium", reward_points=600, company_id=company3.id, category="Cloud Security", tags="AWS,S3,IAM"),
            Task(title="GraphQL API Rate Limiting Bypass", description="Test our GraphQL endpoint for introspection abuse, query batching attacks, and rate limiting bypass techniques. Look for deeply nested query DoS vectors.", difficulty="Hard", reward_points=700, company_id=company3.id, category="API Security", tags="GraphQL,API,RateLimit"),
            Task(title="Subdomain Takeover Scan", description="Enumerate all subdomains and identify dangling DNS records pointing to deprovisioned cloud resources. Check for takeover potential on Azure, AWS, GitHub Pages, and Heroku.", difficulty="Medium", reward_points=400, company_id=company1.id, category="Network Security", tags="DNS,Subdomain,Cloud"),
            Task(title="Phishing Simulation Review", description="Analyze our email filtering and employee security posture against targeted spear-phishing simulations. Identify gaps in SPF, DKIM, and DMARC configuration.", difficulty="Easy", reward_points=200, company_id=company2.id, category="Social Engineering", tags="Phishing,Email,OSINT"),
        ]
        session.add_all(tasks)
        session.commit()
        for t in tasks:
            session.refresh(t)

        # ── Submissions ────────────────────────────────────
        submissions = [
            Submission(task_id=tasks[0].id, user_id=researcher1.id, content="Found reflected XSS in the error message when invalid username is supplied. Payload: <script>alert(document.cookie)</script> in the username field returns unescaped in the error response.", status="rewarded", upvotes=14),
            Submission(task_id=tasks[0].id, user_id=researcher2.id, content="Stored XSS via profile bio field rendered on login page. Any user can inject a persistent payload that executes for all visitors.", status="pending", upvotes=8),
            Submission(task_id=tasks[1].id, user_id=researcher1.id, content="Boolean-based blind SQL injection confirmed in the `user` parameter. Using payload ' OR '1'='1 bypasses authentication entirely. The query appears to be: SELECT * FROM users WHERE username='' OR '1'='1'--", status="rewarded", upvotes=21),
            Submission(task_id=tasks[1].id, user_id=researcher3.id, content="Time-based injection also works: ' OR SLEEP(5)-- causes a 5 second delay confirming the vulnerability. MySQL version leaked via error messages.", status="pending", upvotes=6),
            Submission(task_id=tasks[2].id, user_id=researcher2.id, content="Algorithm confusion attack confirmed. Server accepts HS256 tokens signed with the public RSA key as the HMAC secret. Forged admin token successfully.", status="rewarded", upvotes=18),
            Submission(task_id=tasks[4].id, user_id=researcher4.id, content="Found publicly listable bucket at s3://nexacloud-backups. Contains database dumps from 2023 with plaintext customer emails and hashed passwords.", status="pending", upvotes=11),
            Submission(task_id=tasks[6].id, user_id=researcher5.id, content="Identified 3 dangling CNAME records pointing to deprovisioned Heroku apps. Subdomain api-staging.acmecorp.com is claimable and could be used to serve malicious content.", status="pending", upvotes=5),
        ]
        session.add_all(submissions)
        session.commit()
        for s in submissions:
            session.refresh(s)

        # ── Badges ─────────────────────────────────────────
        badges = [
            Badge(user_id=researcher1.id, task_id=tasks[0].id, badge_type="Vulnerability Finder"),
            Badge(user_id=researcher1.id, task_id=tasks[1].id, badge_type="Critical Gap Hunter"),
            Badge(user_id=researcher2.id, task_id=tasks[2].id, badge_type="Zero Day Scout"),
            Badge(user_id=researcher3.id, task_id=tasks[1].id, badge_type="Security Analyst"),
            Badge(user_id=researcher4.id, task_id=tasks[4].id, badge_type="Bug Slayer"),
        ]
        session.add_all(badges)

        # ── Reputation ─────────────────────────────────────
        researcher1.reputation = 820
        researcher2.reputation = 640
        researcher3.reputation = 380
        researcher4.reputation = 260
        researcher5.reputation = 120

        session.add_all([researcher1, researcher2, researcher3, researcher4, researcher5])
        session.commit()


# -------- User endpoints --------


@app.post("/users")
def create_user(user: dict, session: Session = Depends(get_session)):
    if not user.get("email") or not is_valid_email(user["email"]):
        raise HTTPException(status_code=400, detail="Valid email address is required")
    existing_user = session.exec(select(User).where(User.username == user["username"])).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    existing_email = session.exec(select(User).where(User.email == user["email"])).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = User(
        username=user["username"],
        role=user.get("role", "user"),
        reputation=0,
        email=user["email"],
        password_hash=hash_password(user["password"]) if user.get("password") else None,
    )
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

    def enrich_submission(sub):
        task = session.get(Task, sub.task_id)
        return {
            "id": sub.id,
            "task_id": sub.task_id,
            "task_title": task.title if task else f"Task #{sub.task_id}",
            "content": sub.content,
            "status": sub.status,
            "upvotes": sub.upvotes,
            "created_at": sub.created_at.isoformat(),
        }

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "reputation": user.reputation,
        "bio": user.bio,
        "badges": [
            {
                "id": b.id,
                "badge_type": b.badge_type,
                "task_id": b.task_id,
                "created_at": b.created_at.isoformat(),
            }
            for b in badges
        ],
        "submissions": [enrich_submission(s) for s in submissions],
    }


@app.post("/login")
def login(credentials: dict, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == credentials["username"])).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.password_hash and not verify_password(credentials.get("password", ""), user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password")
    badges = session.exec(select(Badge).where(Badge.user_id == user.id)).all()
    submissions = session.exec(select(Submission).where(Submission.user_id == user.id)).all()
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "reputation": user.reputation,
        "bio": user.bio,
        "badges": [
            {
                "id": b.id,
                "badge_type": b.badge_type,
                "task_id": b.task_id,
                "created_at": b.created_at.isoformat(),
            }
            for b in badges
        ],
        "submissions": [
            {
                "id": s.id,
                "task_id": s.task_id,
                "task_title": session.get(Task, s.task_id).title if session.get(Task, s.task_id) else f"Task #{s.task_id}",
                "content": s.content,
                "status": s.status,
                "upvotes": s.upvotes,
                "created_at": s.created_at.isoformat(),
            }
            for s in submissions
        ],
    }

# -------- Task endpoints --------

@app.get("/debug/badges")
def debug_badges(session: Session = Depends(get_session)):
    all_badges = session.exec(select(Badge)).all()
    return [{"id": b.id, "user_id": b.user_id, "badge_type": b.badge_type} for b in all_badges]

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
def reward_submission(submission_id: int, badge_data: dict = {}, session: Session = Depends(get_session)):
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
        user_id=user.id,
        task_id=task.id,
        badge_type=badge_data.get("badge_type", "Security Finding"),
    )
    submission.status = "rewarded"
    user.reputation += BADGE_REWARD_POINTS
    session.add(badge)
    session.add(submission)
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"message": "Submission rewarded", "user_reputation": user.reputation}

@app.post("/users/{user_id}/badges")
def award_badge(user_id: int, badge_data: dict, session: Session = Depends(get_session)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    badge = Badge(
        user_id=user_id,
        task_id=None,
        badge_type=badge_data["badge_type"],
    )
    user.reputation += 25
    session.add(badge)
    session.add(user)
    session.commit()
    session.refresh(badge)
    return {"id": badge.id, "badge_type": badge.badge_type, "user_id": badge.user_id}


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
