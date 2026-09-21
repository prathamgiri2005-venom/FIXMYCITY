from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import base64
import json
import logging
import math
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from bson import ObjectId
from fastapi import APIRouter, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
from starlette.middleware.cors import CORSMiddleware

from seed import seed_database, refresh_gamification

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

UPLOAD_DIR = ROOT_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALG = "HS256"

CATEGORIES = ["electricity", "roads", "water", "sanitation", "streetlights", "other"]
STATUS_FLOW = ["Pending", "Assigned", "In Progress", "Resolved"]

app = FastAPI(title="FixMyCity API")
api = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)
logger = logging.getLogger("fixmycity")
logging.basicConfig(level=logging.INFO)


# ---------------- auth helpers ----------------

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))


def create_token(user) -> str:
    payload = {
        "sub": str(user["_id"]),
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def pub_user(doc) -> dict:
    return {
        "id": str(doc["_id"]),
        "name": doc.get("name", "Citizen"),
        "email": doc.get("email"),
        "role": doc.get("role", "citizen"),
        "dept": doc.get("dept"),
        "points": doc.get("points", 0),
        "badges": doc.get("badges", []),
    }


async def current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    if not user:
        raise HTTPException(401, "User not found")
    return user


async def require_admin(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required")
    return user


# ---------------- issue serialization ----------------

def iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else v


def pub_issue(doc, me_id: Optional[str] = None) -> dict:
    return {
        "id": str(doc["_id"]),
        "description": doc.get("description", ""),
        "category": doc.get("category", "other"),
        "status": doc.get("status", "Pending"),
        "image_url": doc.get("image_url"),
        "resolution_image": doc.get("resolution_image"),
        "lat": doc.get("lat"),
        "lng": doc.get("lng"),
        "address": doc.get("address", ""),
        "area": doc.get("area", ""),
        "author": {"id": doc.get("author_id"), "name": doc.get("author_name", "Citizen")},
        "upvotes": len(doc.get("upvotes", [])),
        "upvoted": bool(me_id and me_id in doc.get("upvotes", [])),
        "assigned_to": doc.get("assigned_to"),
        "deadline": iso(doc.get("deadline")),
        "timeline": [
            {"status": t.get("status"), "at": iso(t.get("at")), "note": t.get("note", "")}
            for t in doc.get("timeline", [])
        ],
        "ai_confidence": doc.get("ai_confidence"),
        "created_at": iso(doc.get("created_at")),
        "resolved_at": iso(doc.get("resolved_at")),
    }


def haversine_km(lat1, lng1, lat2, lng2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        try:
            return datetime.strptime(str(s)[:10], "%Y-%m-%d")
        except Exception:
            return None


# ---------------- request models ----------------

class RegisterIn(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ClassifyIn(BaseModel):
    image_url: Optional[str] = None
    description: str = ""


class IssueIn(BaseModel):
    description: str
    category: str = "other"
    lat: float
    lng: float
    address: str = ""
    area: str = ""
    image_url: Optional[str] = None
    ai_confidence: Optional[float] = None


class AssignIn(BaseModel):
    worker_id: str
    deadline: Optional[str] = None
    note: Optional[str] = ""


class StatusIn(BaseModel):
    status: str
    note: Optional[str] = ""
    resolution_image: Optional[str] = None


# ---------------- auth routes ----------------

@api.post("/auth/register")
async def register(body: RegisterIn):
    email = body.email.lower().strip()
    if len(body.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if await db.users.find_one({"email": email}):
        raise HTTPException(400, "Email already registered")
    doc = {
        "name": body.name.strip(),
        "email": email,
        "password_hash": hash_password(body.password),
        "role": "citizen",
        "points": 0,
        "badges": [],
        "created_at": datetime.now(timezone.utc),
    }
    res = await db.users.insert_one(doc)
    doc["_id"] = res.inserted_id
    return {"token": create_token(doc), "user": pub_user(doc)}


@api.post("/auth/login")
async def login(body: LoginIn):
    user = await db.users.find_one({"email": body.email.lower().strip()})
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    return {"token": create_token(user), "user": pub_user(user)}


@api.get("/auth/me")
async def me(user=Depends(current_user)):
    return pub_user(user)


# ---------------- uploads ----------------

ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".webp"}


@api.post("/upload")
async def upload(file: UploadFile = File(...), user=Depends(current_user)):
    ext = os.path.splitext(file.filename or "img.jpg")[1].lower()
    if ext not in ALLOWED_EXT:
        ext = ".jpg"
    data = await file.read()
    if len(data) > 12 * 1024 * 1024:
        raise HTTPException(400, "Image too large (max 12MB)")
    fname = f"{uuid.uuid4().hex}{ext}"
    (UPLOAD_DIR / fname).write_bytes(data)
    return {"url": f"/api/uploads/{fname}"}


# ---------------- AI classification ----------------

KEYWORDS = {
    "roads": ["pothole", "road", "asphalt", "crater", "pavement", "footpath", "speed breaker", "caved"],
    "water": ["water", "leak", "pipe", "flood", "sewage", "drain", "overflow", "burst"],
    "sanitation": ["garbage", "trash", "waste", "bin", "debris", "litter", "dump", "smell"],
    "streetlights": ["streetlight", "street light", "lamp", "light pole", "dark", "flickering"],
    "electricity": ["transformer", "wire", "power", "electricity", "electric", "fuse", "sparking"],
}


@api.post("/issues/classify")
async def classify(body: ClassifyIn, user=Depends(current_user)):
    key = os.environ.get("EMERGENT_LLM_KEY")
    if key and body.image_url:
        try:
            rel = body.image_url.split("/api/uploads/")[-1].lstrip("/")
            fpath = (UPLOAD_DIR / rel).resolve()
            if str(fpath).startswith(str(UPLOAD_DIR.resolve())) and fpath.exists():
                b64 = base64.b64encode(fpath.read_bytes()).decode()
                from emergentintegrations.llm.chat import LlmChat, UserMessage, ImageContent

                chat = LlmChat(
                    api_key=key,
                    session_id=f"classify-{uuid.uuid4().hex[:8]}",
                    system_message="You are an AI that classifies civic infrastructure issue photos into exactly one category.",
                ).with_model("openai", "gpt-5.4-mini")
                prompt = (
                    "Classify this civic issue photo into EXACTLY ONE of these categories: "
                    "electricity, roads, water, sanitation, streetlights, other.\n"
                    f"Citizen description (may be empty): {body.description[:300]}\n"
                    'Respond with ONLY a JSON object: {"category": "<one of the categories>", '
                    '"confidence": <0.0-1.0>, "reason": "<one short sentence>"}'
                )
                resp = await chat.send_message(
                    UserMessage(text=prompt, file_contents=[ImageContent(image_base64=b64)])
                )
                m = re.search(r"\{.*\}", resp, re.S)
                data = json.loads(m.group(0))
                cat = str(data.get("category", "")).lower().strip()
                if cat in CATEGORIES:
                    return {
                        "category": cat,
                        "confidence": min(0.99, max(0.5, float(data.get("confidence", 0.85)))),
                        "reason": str(data.get("reason", ""))[:200],
                        "source": "ai",
                    }
        except Exception as e:
            logger.warning(f"AI classify failed, using fallback: {e}")
    text = (body.description or "").lower()
    for cat, words in KEYWORDS.items():
        if any(w in text for w in words):
            return {"category": cat, "confidence": 0.6, "reason": "Matched keywords in description", "source": "keyword"}
    return {"category": "other", "confidence": 0.4, "reason": "No strong signal detected", "source": "fallback"}


# ---------------- issues ----------------

@api.post("/issues")
async def create_issue(body: IssueIn, user=Depends(current_user)):
    cat = body.category if body.category in CATEGORIES else "other"
    now = datetime.now(timezone.utc)
    doc = {
        "description": body.description.strip(),
        "category": cat,
        "status": "Pending",
        "image_url": body.image_url,
        "resolution_image": None,
        "lat": body.lat,
        "lng": body.lng,
        "address": body.address.strip(),
        "area": body.area.strip() or "Unspecified",
        "author_id": str(user["_id"]),
        "author_name": user.get("name", "Citizen"),
        "upvotes": [],
        "assigned_to": None,
        "deadline": None,
        "timeline": [{"status": "Pending", "at": now, "note": "Report submitted"}],
        "ai_confidence": body.ai_confidence,
        "created_at": now,
        "resolved_at": None,
    }
    res = await db.issues.insert_one(doc)
    doc["_id"] = res.inserted_id
    await refresh_gamification(db, user["_id"])
    return pub_issue(doc, str(user["_id"]))


@api.get("/issues")
async def list_issues(
    status: Optional[str] = None,
    category: Optional[str] = None,
    area: Optional[str] = None,
    lat: Optional[float] = None,
    lng: Optional[float] = None,
    sort: str = "recent",
    user=Depends(current_user),
):
    q = {}
    if status and status != "all":
        q["status"] = status
    if category and category != "all":
        q["category"] = category
    if area:
        q["area"] = {"$regex": area, "$options": "i"}
    docs = await db.issues.find(q).to_list(2000)
    me_id = str(user["_id"])
    out = []
    for d in docs:
        item = pub_issue(d, me_id)
        if lat is not None and lng is not None and d.get("lat") and d.get("lng"):
            item["distance_km"] = round(haversine_km(lat, lng, d["lat"], d["lng"]), 1)
        else:
            item["distance_km"] = None
        out.append(item)
    if sort == "nearest" and lat is not None:
        out.sort(key=lambda x: (x["distance_km"] is None, x["distance_km"] or 0))
    elif sort == "top":
        out.sort(key=lambda x: -x["upvotes"])
    else:
        out.sort(key=lambda x: x["created_at"] or "", reverse=True)
    return out


@api.get("/issues/mine")
async def my_issues(user=Depends(current_user)):
    docs = await db.issues.find({"author_id": str(user["_id"])}).to_list(500)
    out = [pub_issue(d, str(user["_id"])) for d in docs]
    out.sort(key=lambda x: x["created_at"] or "", reverse=True)
    return out


@api.post("/issues/{issue_id}/upvote")
async def upvote(issue_id: str, user=Depends(current_user)):
    try:
        oid = ObjectId(issue_id)
    except Exception:
        raise HTTPException(404, "Issue not found")
    doc = await db.issues.find_one({"_id": oid})
    if not doc:
        raise HTTPException(404, "Issue not found")
    me_id = str(user["_id"])
    upvotes = doc.get("upvotes", [])
    if me_id in upvotes:
        await db.issues.update_one({"_id": oid}, {"$pull": {"upvotes": me_id}})
    elif doc.get("author_id") != me_id:
        await db.issues.update_one({"_id": oid}, {"$push": {"upvotes": me_id}})
    doc = await db.issues.find_one({"_id": oid})
    return pub_issue(doc, me_id)


# ---------------- admin ----------------

@api.get("/workers")
async def list_workers(admin=Depends(require_admin)):
    docs = await db.users.find({"role": "worker"}).to_list(100)
    out = []
    for w in docs:
        resolved = await db.issues.count_documents({"assigned_to.id": str(w["_id"]), "status": "Resolved"})
        active = await db.issues.count_documents({"assigned_to.id": str(w["_id"]), "status": {"$in": ["Assigned", "In Progress"]}})
        u = pub_user(w)
        u["resolved_count"] = resolved
        u["active_count"] = active
        out.append(u)
    return out


@api.patch("/issues/{issue_id}/assign")
async def assign_issue(issue_id: str, body: AssignIn, admin=Depends(require_admin)):
    try:
        oid = ObjectId(issue_id)
        woid = ObjectId(body.worker_id)
    except Exception:
        raise HTTPException(400, "Invalid id")
    issue = await db.issues.find_one({"_id": oid})
    worker = await db.users.find_one({"_id": woid, "role": "worker"})
    if not issue:
        raise HTTPException(404, "Issue not found")
    if not worker:
        raise HTTPException(404, "Worker not found")
    now = datetime.now(timezone.utc)
    new_status = "Assigned" if issue["status"] == "Pending" else issue["status"]
    update = {
        "assigned_to": {"id": str(worker["_id"]), "name": worker["name"], "dept": worker.get("dept", "Field Ops")},
        "deadline": parse_dt(body.deadline),
        "status": new_status,
    }
    note = body.note or f"Assigned to {worker['name']} ({worker.get('dept', 'Field Ops')})"
    await db.issues.update_one(
        {"_id": oid},
        {"$set": update, "$push": {"timeline": {"status": "Assigned", "at": now, "note": note}}},
    )
    doc = await db.issues.find_one({"_id": oid})
    return pub_issue(doc, str(admin["_id"]))


@api.patch("/issues/{issue_id}/status")
async def update_status(issue_id: str, body: StatusIn, user=Depends(current_user)):
    if body.status not in STATUS_FLOW:
        raise HTTPException(400, "Invalid status")
    try:
        oid = ObjectId(issue_id)
    except Exception:
        raise HTTPException(404, "Issue not found")
    issue = await db.issues.find_one({"_id": oid})
    if not issue:
        raise HTTPException(404, "Issue not found")
    me_id = str(user["_id"])
    if user["role"] == "worker":
        assigned = (issue.get("assigned_to") or {}).get("id")
        if assigned != me_id:
            raise HTTPException(403, "Not your assigned task")
        if body.status not in ("In Progress", "Resolved"):
            raise HTTPException(403, "Workers can only set In Progress or Resolved")
    elif user["role"] != "admin":
        raise HTTPException(403, "Not allowed")
    now = datetime.now(timezone.utc)
    update = {"status": body.status}
    if body.status == "Resolved":
        update["resolved_at"] = now
        if body.resolution_image:
            update["resolution_image"] = body.resolution_image
    note = body.note or f"Status changed to {body.status}"
    await db.issues.update_one(
        {"_id": oid}, {"$set": update, "$push": {"timeline": {"status": body.status, "at": now, "note": note}}}
    )
    if body.status == "Resolved" and issue["status"] != "Resolved":
        try:
            await refresh_gamification(db, ObjectId(issue["author_id"]))
        except Exception:
            pass
        assigned = (issue.get("assigned_to") or {}).get("id")
        if assigned:
            try:
                await refresh_gamification(db, ObjectId(assigned))
            except Exception:
                pass
    doc = await db.issues.find_one({"_id": oid})
    return pub_issue(doc, me_id)


@api.get("/tasks")
async def tasks(worker_id: Optional[str] = None, user=Depends(current_user)):
    if user["role"] == "worker":
        wid = str(user["_id"])
    elif user["role"] == "admin":
        wid = worker_id
    else:
        raise HTTPException(403, "Not allowed")
    q = {"assigned_to": {"$ne": None}}
    if wid:
        q["assigned_to.id"] = wid
    docs = await db.issues.find(q).to_list(500)
    out = [pub_issue(d, str(user["_id"])) for d in docs]
    order = {"In Progress": 0, "Assigned": 1, "Resolved": 2, "Pending": 3}
    out.sort(key=lambda x: (order.get(x["status"], 4), x["deadline"] or "9999"))
    return out


@api.get("/analytics")
async def analytics(admin=Depends(require_admin)):
    issues = await db.issues.find().to_list(5000)
    by_status = {s: 0 for s in STATUS_FLOW}
    by_category = {c: 0 for c in CATEGORIES}
    area_map = {}
    res_hours = []
    today = datetime.now(timezone.utc).date()
    trend = {}
    for i in range(13, -1, -1):
        d = today - timedelta(days=i)
        trend[d.isoformat()] = {"date": d.strftime("%b %d"), "reported": 0, "resolved": 0}
    for it in issues:
        by_status[it["status"]] = by_status.get(it["status"], 0) + 1
        by_category[it.get("category", "other")] = by_category.get(it.get("category", "other"), 0) + 1
        area = it.get("area") or "Unknown"
        area_map[area] = area_map.get(area, 0) + 1
        ca, ra = it.get("created_at"), it.get("resolved_at")
        if ca and ca.date().isoformat() in trend:
            trend[ca.date().isoformat()]["reported"] += 1
        if ra:
            if ra.date().isoformat() in trend:
                trend[ra.date().isoformat()]["resolved"] += 1
            if ca:
                res_hours.append(max((ra - ca).total_seconds() / 3600.0, 0.5))
    avg_res = round(sum(res_hours) / len(res_hours), 1) if res_hours else 0
    resolved = by_status.get("Resolved", 0)
    return {
        "total": len(issues),
        "active": len(issues) - resolved,
        "resolved": resolved,
        "resolution_rate": round(100 * resolved / len(issues), 1) if issues else 0,
        "avg_resolution_hours": avg_res,
        "by_status": [{"name": k, "value": v} for k, v in by_status.items()],
        "by_category": [{"name": k, "value": v} for k, v in by_category.items()],
        "by_area": sorted([{"name": k, "value": v} for k, v in area_map.items()], key=lambda x: -x["value"])[:8],
        "trend": list(trend.values()),
    }


# ---------------- public / gamification ----------------

@api.get("/public/stats")
async def public_stats():
    total = await db.issues.count_documents({})
    resolved = await db.issues.count_documents({"status": "Resolved"})
    citizens = await db.users.count_documents({"role": "citizen"})
    return {"total": total, "resolved": resolved, "citizens": citizens}


@api.get("/leaderboard")
async def leaderboard(user=Depends(current_user)):
    docs = await db.users.find({"role": "citizen"}).sort("points", -1).to_list(20)
    out = []
    for i, u in enumerate(docs):
        reports = await db.issues.count_documents({"author_id": str(u["_id"])})
        resolved = await db.issues.count_documents({"author_id": str(u["_id"]), "status": "Resolved"})
        out.append(
            {
                "rank": i + 1,
                "id": str(u["_id"]),
                "name": u.get("name", "Citizen"),
                "points": u.get("points", 0),
                "badges": u.get("badges", []),
                "reports": reports,
                "resolved": resolved,
            }
        )
    return out


@api.get("/")
async def root():
    return {"message": "FixMyCity API running"}


app.include_router(api)
app.mount("/api/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

   app.add_middleware(
       CORSMiddleware,
       allow_credentials=True,
       allow_origin_regex=r"https://.*\.vercel\.app",
       allow_methods=["*"],
       allow_headers=["*"],
   )


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.issues.create_index("status")
    await db.issues.create_index("category")
    await seed_database(db)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
