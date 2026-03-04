from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import sqlite3, os, bcrypt, jwt, datetime, shutil, glob, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("edh-vault")

app = FastAPI(title="EDH Vault API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DB_PATH    = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "edh.db"))
JWT_SECRET = os.environ.get("JWT_SECRET", "change-this-in-production-please")
JWT_ALG    = "HS256"
JWT_EXP_H  = 72  # token lives 72 hours

bearer = HTTPBearer(auto_error=False)

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    if os.path.dirname(DB_PATH):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
            pw_hash    TEXT NOT NULL,
            is_admin   INTEGER DEFAULT 0,
            is_active  INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS decks (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name           TEXT NOT NULL,
            commander      TEXT NOT NULL,
            partner        TEXT,
            colors         TEXT NOT NULL DEFAULT '',
            color_identity TEXT NOT NULL,
            archetype      TEXT NOT NULL,
            power_level    INTEGER CHECK(power_level BETWEEN 1 AND 5),
            status         TEXT DEFAULT 'Active',
            notes          TEXT,
            created_at     TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS games (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            date             TEXT NOT NULL,
            location         TEXT,
            my_deck_id       INTEGER REFERENCES decks(id) ON DELETE SET NULL,
            opp1_commander   TEXT, opp1_colors TEXT, opp1_archetype TEXT,
            opp2_commander   TEXT, opp2_colors TEXT, opp2_archetype TEXT,
            opp3_commander   TEXT, opp3_colors TEXT, opp3_archetype TEXT,
            winner_commander TEXT,
            win_condition    TEXT,
            i_won            INTEGER DEFAULT 0,
            notes            TEXT,
            created_at       TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS opponents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name        TEXT NOT NULL,
            commander   TEXT,
            colors      TEXT,
            archetype   TEXT,
            power_level INTEGER,
            notes       TEXT,
            UNIQUE(user_id, name)
        );
        """)
    _seed_accounts()

def _hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def _check(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def _seed_accounts():
    """Ensure default accounts exist on every startup (idempotent)."""
    seeds = [
        ("admin",   os.environ.get("ADMIN_PASSWORD", "admin1234"), 1),
        ("Player1", "1234", 0),
        ("Player2", "4321", 0),
    ]
    with get_db() as c:
        for username, pw, is_admin in seeds:
            if not c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                c.execute("INSERT INTO users (username,pw_hash,is_admin) VALUES (?,?,?)",
                          (username, _hash(pw), is_admin))
        c.commit()

init_db()

# ── Migrations ────────────────────────────────────────────────────────────────
# Rules:
#   • NEVER edit or delete an existing entry — only append new ones.
#   • Each entry runs exactly once per database, ever.
#   • Safe operations: ADD COLUMN, CREATE TABLE, CREATE INDEX, UPDATE, INSERT.
#   • For destructive changes (rename/drop), use a multi-step entry:
#     create new column → copy data → leave old column (SQLite can't drop columns
#     directly without recreating the whole table).
MIGRATIONS: List[str] = [
    # v1: baseline schema established by init_db(). No-op, just records the version.
    "SELECT 1",

    # ── Append new migrations below. Never edit lines above this comment. ──────
    # Example (remove leading # to activate):
    # "ALTER TABLE decks ADD COLUMN format TEXT DEFAULT 'Commander'",
    # "ALTER TABLE games ADD COLUMN pod_size INTEGER",
    # "CREATE INDEX IF NOT EXISTS idx_games_user_date ON games(user_id, date)",
]

def run_migrations():
    """Apply any pending migrations in order. Safe to call on every startup."""
    with get_db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT DEFAULT (datetime('now'))
        )""")
        row = c.execute("SELECT MAX(version) FROM schema_version").fetchone()
        current = row[0] or 0
        pending = [(i + 1, sql) for i, sql in enumerate(MIGRATIONS) if i + 1 > current]
        if not pending:
            log.info(f"DB schema up to date (v{current})")
            return
        for version, sql in pending:
            log.info(f"Applying migration v{version}: {sql[:80]}")
            c.execute(sql)
            c.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
        c.commit()
        log.info(f"Migrations done: v{current} → v{version}")

# ── Backups ───────────────────────────────────────────────────────────────────
# BACKUP_DIR: where backups are written. On Render with a persistent disk,
#   set this to a path on the disk, e.g. /data/backups (via env var).
# BACKUP_KEEP: number of most-recent backups to retain; older ones are pruned.
BACKUP_DIR  = os.environ.get("BACKUP_DIR",  os.path.join(os.path.dirname(DB_PATH) or ".", "backups"))
BACKUP_KEEP = int(os.environ.get("BACKUP_KEEP", "14"))

def backup_db() -> Optional[str]:
    """
    Snapshot the live DB using SQLite's online backup API.
    This is safe even with concurrent writes — SQLite handles it atomically.
    Returns the backup file path, or None if the DB doesn't exist yet.
    """
    if not os.path.exists(DB_PATH):
        log.info("backup_db: no DB file yet, skipping")
        return None
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"edh_{ts}.db")
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(dest)
    with dst:
        src.backup(dst)
    src.close(); dst.close()
    log.info(f"Backup written: {dest}")
    _prune_backups()
    return dest

def _prune_backups():
    """Remove oldest backups, keeping only the BACKUP_KEEP most recent."""
    files = sorted(glob.glob(os.path.join(BACKUP_DIR, "edh_*.db")))
    for f in files[:max(0, len(files) - BACKUP_KEEP)]:
        os.remove(f)
        log.info(f"Pruned backup: {f}")

# Run on every startup
run_migrations()
backup_db()

# ── JWT ───────────────────────────────────────────────────────────────────────
def make_token(user_id: int, username: str, is_admin: bool) -> str:
    return jwt.encode({
        "sub": user_id, "username": username, "admin": is_admin,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXP_H)
    }, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired — please log in again")
    except Exception:
        raise HTTPException(401, "Invalid token")

def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    if not creds:
        raise HTTPException(401, "Not authenticated")
    return decode_token(creds.credentials)

def current_admin(user: dict = Depends(current_user)) -> dict:
    if not user.get("admin"):
        raise HTTPException(403, "Admin only")
    return user

# ── Pydantic models ───────────────────────────────────────────────────────────
class AuthIn(BaseModel):
    username: str; password: str

class DeckIn(BaseModel):
    name: str; commander: str; partner: Optional[str] = None
    colors: str = ""; color_identity: str; archetype: str
    power_level: Optional[int] = None; status: str = "Active"; notes: Optional[str] = None

class GameIn(BaseModel):
    date: str; location: Optional[str]=None; my_deck_id: Optional[int]=None
    opp1_commander: Optional[str]=None; opp1_colors: Optional[str]=None; opp1_archetype: Optional[str]=None
    opp2_commander: Optional[str]=None; opp2_colors: Optional[str]=None; opp2_archetype: Optional[str]=None
    opp3_commander: Optional[str]=None; opp3_colors: Optional[str]=None; opp3_archetype: Optional[str]=None
    winner_commander: Optional[str]=None; win_condition: Optional[str]=None
    i_won: int=0; notes: Optional[str]=None

class OpponentIn(BaseModel):
    name: str; commander: Optional[str]=None; colors: Optional[str]=None
    archetype: Optional[str]=None; power_level: Optional[int]=None; notes: Optional[str]=None

class AdminUserPatch(BaseModel):
    is_active: Optional[bool]=None; is_admin: Optional[bool]=None; password: Optional[str]=None

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/register", status_code=201)
def register(body: AuthIn):
    u = body.username.strip()
    if len(u) < 2:   raise HTTPException(400, "Username must be at least 2 characters")
    if len(body.password) < 4: raise HTTPException(400, "Password must be at least 4 characters")
    # Block reserved names
    if u.lower() in ("admin", "administrator"):
        raise HTTPException(400, "That username is reserved")
    with get_db() as c:
        if c.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone():
            raise HTTPException(409, "Username already taken")
        row = c.execute("INSERT INTO users (username,pw_hash) VALUES (?,?) RETURNING id",
                        (u, _hash(body.password))).fetchone()
        c.commit()
    return {"token": make_token(row["id"], u, False), "username": u, "is_admin": False}

@app.post("/api/auth/login")
def login(body: AuthIn):
    with get_db() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (body.username.strip(),)).fetchone()
    if not row or not _check(body.password, row["pw_hash"]):
        raise HTTPException(401, "Invalid username or password")
    if not row["is_active"]:
        raise HTTPException(403, "This account has been disabled")
    return {"token": make_token(row["id"], row["username"], bool(row["is_admin"])),
            "username": row["username"], "is_admin": bool(row["is_admin"])}

@app.get("/api/auth/me")
def me(user: dict = Depends(current_user)):
    return {"user_id": user["sub"], "username": user["username"], "is_admin": user["admin"]}

# ── Community (any logged-in user can see; no private deck names exposed) ─────
@app.get("/api/community")
def community(_: dict = Depends(current_user)):
    with get_db() as c:
        users = c.execute(
            "SELECT id, username FROM users WHERE is_active=1 AND is_admin=0 ORDER BY username"
        ).fetchall()
        result = []
        for u in users:
            decks = c.execute("""
                SELECT commander, partner, color_identity FROM decks
                WHERE user_id=? AND status='Active' ORDER BY commander""", (u["id"],)).fetchall()
            result.append({
                "username": u["username"],
                "commanders": [{"name": d["commander"] + (" + " + d["partner"] if d["partner"] else ""),
                                "identity": d["color_identity"]} for d in decks]
            })
    return result

# ── Decks ─────────────────────────────────────────────────────────────────────
@app.get("/api/decks")
def list_decks(user: dict = Depends(current_user)):
    with get_db() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM decks WHERE user_id=? ORDER BY name", (user["sub"],)).fetchall()]

@app.post("/api/decks", status_code=201)
def create_deck(d: DeckIn, user: dict = Depends(current_user)):
    with get_db() as c:
        cur = c.execute(
            "INSERT INTO decks (user_id,name,commander,partner,colors,color_identity,archetype,power_level,status,notes) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (user["sub"],d.name,d.commander,d.partner,d.colors,d.color_identity,d.archetype,d.power_level,d.status,d.notes))
        c.commit(); return {"id": cur.lastrowid, **d.dict()}

@app.put("/api/decks/{did}")
def update_deck(did: int, d: DeckIn, user: dict = Depends(current_user)):
    with get_db() as c:
        row = c.execute("SELECT user_id FROM decks WHERE id=?", (did,)).fetchone()
        if not row: raise HTTPException(404, "Deck not found")
        if row["user_id"] != user["sub"]: raise HTTPException(403, "Not your deck")
        c.execute("UPDATE decks SET name=?,commander=?,partner=?,colors=?,color_identity=?,archetype=?,power_level=?,status=?,notes=? WHERE id=?",
            (d.name,d.commander,d.partner,d.colors,d.color_identity,d.archetype,d.power_level,d.status,d.notes,did))
        c.commit(); return {"id": did, **d.dict()}

@app.delete("/api/decks/{did}")
def delete_deck(did: int, user: dict = Depends(current_user)):
    with get_db() as c:
        row = c.execute("SELECT user_id FROM decks WHERE id=?", (did,)).fetchone()
        if not row: raise HTTPException(404)
        if row["user_id"] != user["sub"]: raise HTTPException(403)
        c.execute("DELETE FROM decks WHERE id=?", (did,)); c.commit()
    return {"deleted": did}

# ── Games ─────────────────────────────────────────────────────────────────────
@app.get("/api/games")
def list_games(user: dict = Depends(current_user)):
    with get_db() as c:
        return [dict(r) for r in c.execute("""
            SELECT g.*, d.name as deck_name, d.commander as my_commander
            FROM games g LEFT JOIN decks d ON g.my_deck_id=d.id
            WHERE g.user_id=? ORDER BY g.date DESC, g.id DESC""", (user["sub"],)).fetchall()]

@app.post("/api/games", status_code=201)
def create_game(g: GameIn, user: dict = Depends(current_user)):
    with get_db() as c:
        cur = c.execute("""INSERT INTO games
            (user_id,date,location,my_deck_id,
             opp1_commander,opp1_colors,opp1_archetype,
             opp2_commander,opp2_colors,opp2_archetype,
             opp3_commander,opp3_colors,opp3_archetype,
             winner_commander,win_condition,i_won,notes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (user["sub"],g.date,g.location,g.my_deck_id,
             g.opp1_commander,g.opp1_colors,g.opp1_archetype,
             g.opp2_commander,g.opp2_colors,g.opp2_archetype,
             g.opp3_commander,g.opp3_colors,g.opp3_archetype,
             g.winner_commander,g.win_condition,g.i_won,g.notes))
        c.commit(); return {"id": cur.lastrowid, **g.dict()}

@app.put("/api/games/{gid}")
def update_game(gid: int, g: GameIn, user: dict = Depends(current_user)):
    with get_db() as c:
        row = c.execute("SELECT user_id FROM games WHERE id=?", (gid,)).fetchone()
        if not row: raise HTTPException(404)
        if row["user_id"] != user["sub"]: raise HTTPException(403)
        c.execute("""UPDATE games SET date=?,location=?,my_deck_id=?,
            opp1_commander=?,opp1_colors=?,opp1_archetype=?,
            opp2_commander=?,opp2_colors=?,opp2_archetype=?,
            opp3_commander=?,opp3_colors=?,opp3_archetype=?,
            winner_commander=?,win_condition=?,i_won=?,notes=? WHERE id=?""",
            (g.date,g.location,g.my_deck_id,
             g.opp1_commander,g.opp1_colors,g.opp1_archetype,
             g.opp2_commander,g.opp2_colors,g.opp2_archetype,
             g.opp3_commander,g.opp3_colors,g.opp3_archetype,
             g.winner_commander,g.win_condition,g.i_won,g.notes,gid))
        c.commit(); return {"id": gid, **g.dict()}

@app.delete("/api/games/{gid}")
def delete_game(gid: int, user: dict = Depends(current_user)):
    with get_db() as c:
        row = c.execute("SELECT user_id FROM games WHERE id=?", (gid,)).fetchone()
        if not row: raise HTTPException(404)
        if row["user_id"] != user["sub"]: raise HTTPException(403)
        c.execute("DELETE FROM games WHERE id=?", (gid,)); c.commit()
    return {"deleted": gid}

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats(user: dict = Depends(current_user)):
    uid = user["sub"]
    with get_db() as c:
        total = c.execute("SELECT COUNT(*) FROM games WHERE user_id=?", (uid,)).fetchone()[0]
        wins  = c.execute("SELECT COUNT(*) FROM games WHERE user_id=? AND i_won=1", (uid,)).fetchone()[0]
        deck_stats = [dict(r) for r in c.execute("""
            SELECT d.id, d.name, d.commander, d.color_identity, d.archetype, d.colors,
                   COUNT(g.id) as games_played,
                   COALESCE(SUM(g.i_won),0) as wins,
                   ROUND(CAST(COALESCE(SUM(g.i_won),0) AS FLOAT)/NULLIF(COUNT(g.id),0)*100,1) as win_pct,
                   MAX(g.date) as last_played
            FROM decks d LEFT JOIN games g ON d.id=g.my_deck_id AND g.user_id=?
            WHERE d.user_id=? GROUP BY d.id ORDER BY games_played DESC, d.name""",
            (uid,uid)).fetchall()]
        win_conds = [dict(r) for r in c.execute("""
            SELECT win_condition, COUNT(*) as count FROM games
            WHERE user_id=? AND win_condition IS NOT NULL AND win_condition!=''
            GROUP BY win_condition ORDER BY count DESC LIMIT 8""", (uid,)).fetchall()]
        recent = [dict(r) for r in c.execute("""
            SELECT g.*, d.name as deck_name FROM games g
            LEFT JOIN decks d ON g.my_deck_id=d.id
            WHERE g.user_id=? ORDER BY g.date DESC, g.id DESC LIMIT 10""", (uid,)).fetchall()]
    return {"total_games":total,"total_wins":wins,
            "win_rate": round(wins/total*100,1) if total else 0,
            "deck_stats":deck_stats,"win_conditions":win_conds,"recent_games":recent}

# ── Opponents ─────────────────────────────────────────────────────────────────
@app.get("/api/opponents")
def list_opponents(user: dict = Depends(current_user)):
    with get_db() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM opponents WHERE user_id=? ORDER BY name", (user["sub"],)).fetchall()]

@app.post("/api/opponents", status_code=201)
def create_opponent(o: OpponentIn, user: dict = Depends(current_user)):
    with get_db() as c:
        try:
            cur = c.execute(
                "INSERT INTO opponents (user_id,name,commander,colors,archetype,power_level,notes) VALUES (?,?,?,?,?,?,?)",
                (user["sub"],o.name,o.commander,o.colors,o.archetype,o.power_level,o.notes))
            c.commit(); return {"id": cur.lastrowid, **o.dict()}
        except sqlite3.IntegrityError:
            raise HTTPException(409, "You already have an opponent with that name")

@app.delete("/api/opponents/{oid}")
def delete_opponent(oid: int, user: dict = Depends(current_user)):
    with get_db() as c:
        row = c.execute("SELECT user_id FROM opponents WHERE id=?", (oid,)).fetchone()
        if not row: raise HTTPException(404)
        if row["user_id"] != user["sub"]: raise HTTPException(403)
        c.execute("DELETE FROM opponents WHERE id=?", (oid,)); c.commit()
    return {"deleted": oid}

# ── Admin ─────────────────────────────────────────────────────────────────────
@app.get("/api/admin/stats")
def admin_stats(_: dict = Depends(current_admin)):
    with get_db() as c:
        return {
            "total_users":  c.execute("SELECT COUNT(*) FROM users WHERE is_admin=0").fetchone()[0],
            "active_users": c.execute("SELECT COUNT(*) FROM users WHERE is_active=1 AND is_admin=0").fetchone()[0],
            "total_decks":  c.execute("SELECT COUNT(*) FROM decks").fetchone()[0],
            "total_games":  c.execute("SELECT COUNT(*) FROM games").fetchone()[0],
            "recent_signups": [dict(r) for r in c.execute(
                "SELECT username, created_at FROM users WHERE is_admin=0 ORDER BY created_at DESC LIMIT 5"
            ).fetchall()],
        }

@app.get("/api/admin/users")
def admin_list_users(_: dict = Depends(current_admin)):
    with get_db() as c:
        rows = c.execute("""
            SELECT u.id, u.username, u.is_admin, u.is_active, u.created_at,
                   COUNT(DISTINCT d.id) as deck_count,
                   COUNT(DISTINCT g.id) as game_count
            FROM users u
            LEFT JOIN decks  d ON d.user_id=u.id
            LEFT JOIN games  g ON g.user_id=u.id
            GROUP BY u.id ORDER BY u.created_at""").fetchall()
    return [dict(r) for r in rows]

@app.patch("/api/admin/users/{uid}")
def admin_patch_user(uid: int, body: AdminUserPatch, admin: dict = Depends(current_admin)):
    if uid == admin["sub"] and body.is_active is False:
        raise HTTPException(400, "Cannot disable your own account")
    with get_db() as c:
        if not c.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone():
            raise HTTPException(404, "User not found")
        if body.is_active is not None:
            c.execute("UPDATE users SET is_active=? WHERE id=?", (int(body.is_active), uid))
        if body.is_admin is not None:
            c.execute("UPDATE users SET is_admin=? WHERE id=?", (int(body.is_admin), uid))
        if body.password:
            if len(body.password) < 4: raise HTTPException(400, "Password too short")
            c.execute("UPDATE users SET pw_hash=? WHERE id=?", (_hash(body.password), uid))
        c.commit()
    return {"updated": uid}

@app.delete("/api/admin/users/{uid}")
def admin_delete_user(uid: int, admin: dict = Depends(current_admin)):
    if uid == admin["sub"]:
        raise HTTPException(400, "Cannot delete your own account")
    with get_db() as c:
        if not c.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone():
            raise HTTPException(404)
        c.execute("DELETE FROM users WHERE id=?", (uid,))  # CASCADE handles decks/games/opponents
        c.commit()
    return {"deleted": uid}

# ── Admin: backups ───────────────────────────────────────────────────────────
from fastapi.responses import FileResponse as _FileResponse

@app.get("/api/admin/backups")
def admin_list_backups(_: dict = Depends(current_admin)):
    """List available backup files."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    files = sorted(glob.glob(os.path.join(BACKUP_DIR, "edh_*.db")), reverse=True)
    result = []
    for f in files:
        stat = os.stat(f)
        result.append({
            "filename": os.path.basename(f),
            "size_kb":  round(stat.st_size / 1024, 1),
            "created":  datetime.datetime.utcfromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M UTC"),
        })
    return result

@app.post("/api/admin/backups")
def admin_create_backup(_: dict = Depends(current_admin)):
    """Manually trigger a backup."""
    path = backup_db()
    if not path:
        raise HTTPException(500, "Database not found — nothing to back up")
    return {"filename": os.path.basename(path), "message": "Backup created"}

@app.get("/api/admin/backups/{filename}")
def admin_download_backup(filename: str, _: dict = Depends(current_admin)):
    """Download a specific backup file."""
    # Sanitise filename — no path traversal
    if "/" in filename or "\\" in filename or not filename.endswith(".db"):
        raise HTTPException(400, "Invalid filename")
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Backup not found")
    return _FileResponse(path, media_type="application/octet-stream",
                         headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.get("/api/admin/schema_version")
def admin_schema_version(_: dict = Depends(current_admin)):
    with get_db() as c:
        row = c.execute("SELECT MAX(version) as v FROM schema_version").fetchone()
    return {"version": row["v"] or 0, "total_migrations": len(MIGRATIONS)}

# ── Frontend ──────────────────────────────────────────────────────────────────
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(frontend_dir):
    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_frontend(full_path: str):
        return FileResponse(os.path.join(frontend_dir, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), reload=True)
