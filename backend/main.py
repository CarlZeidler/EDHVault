from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3, os

app = FastAPI(title="EDH Vault API")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# DB_PATH: use env var so Render persistent disk works (/data/edh.db)
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "edh.db"))

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True) if os.path.dirname(DB_PATH) else None
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS decks (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            commander     TEXT NOT NULL,
            partner       TEXT,
            colors        TEXT NOT NULL,
            color_identity TEXT NOT NULL,
            archetype     TEXT NOT NULL,
            power_level   INTEGER CHECK(power_level BETWEEN 1 AND 10),
            status        TEXT DEFAULT 'Active',
            notes         TEXT,
            created_at    TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS games (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            date             TEXT NOT NULL,
            location         TEXT,
            my_deck_id       INTEGER REFERENCES decks(id) ON DELETE SET NULL,
            opp1_commander   TEXT,
            opp1_colors      TEXT,
            opp1_archetype   TEXT,
            opp2_commander   TEXT,
            opp2_colors      TEXT,
            opp2_archetype   TEXT,
            opp3_commander   TEXT,
            opp3_colors      TEXT,
            opp3_archetype   TEXT,
            winner_commander TEXT,
            win_condition    TEXT,
            i_won            INTEGER DEFAULT 0,
            notes            TEXT,
            created_at       TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS opponents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            commander   TEXT,
            colors      TEXT,
            archetype   TEXT,
            power_level INTEGER,
            notes       TEXT
        );
        """)

init_db()

# ── Pydantic Models ────────────────────────────────────────────────────────
class DeckIn(BaseModel):
    name: str; commander: str; partner: Optional[str] = None
    colors: str; color_identity: str; archetype: str
    power_level: Optional[int] = None; status: str = "Active"; notes: Optional[str] = None

class GameIn(BaseModel):
    date: str; location: Optional[str] = None; my_deck_id: Optional[int] = None
    opp1_commander: Optional[str] = None; opp1_colors: Optional[str] = None; opp1_archetype: Optional[str] = None
    opp2_commander: Optional[str] = None; opp2_colors: Optional[str] = None; opp2_archetype: Optional[str] = None
    opp3_commander: Optional[str] = None; opp3_colors: Optional[str] = None; opp3_archetype: Optional[str] = None
    winner_commander: Optional[str] = None; win_condition: Optional[str] = None
    i_won: int = 0; notes: Optional[str] = None

class OpponentIn(BaseModel):
    name: str; commander: Optional[str] = None; colors: Optional[str] = None
    archetype: Optional[str] = None; power_level: Optional[int] = None; notes: Optional[str] = None

# ── Decks ──────────────────────────────────────────────────────────────────
@app.get("/api/decks")
def list_decks():
    with get_db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM decks ORDER BY name").fetchall()]

@app.post("/api/decks", status_code=201)
def create_deck(d: DeckIn):
    with get_db() as c:
        cur = c.execute("INSERT INTO decks (name,commander,partner,colors,color_identity,archetype,power_level,status,notes) VALUES (?,?,?,?,?,?,?,?,?)",
            (d.name,d.commander,d.partner,d.colors,d.color_identity,d.archetype,d.power_level,d.status,d.notes))
        c.commit(); return {"id": cur.lastrowid, **d.dict()}

@app.put("/api/decks/{did}")
def update_deck(did: int, d: DeckIn):
    with get_db() as c:
        c.execute("UPDATE decks SET name=?,commander=?,partner=?,colors=?,color_identity=?,archetype=?,power_level=?,status=?,notes=? WHERE id=?",
            (d.name,d.commander,d.partner,d.colors,d.color_identity,d.archetype,d.power_level,d.status,d.notes,did))
        c.commit(); return {"id": did, **d.dict()}

@app.delete("/api/decks/{did}")
def delete_deck(did: int):
    with get_db() as c:
        c.execute("DELETE FROM decks WHERE id=?", (did,)); c.commit(); return {"deleted": did}

# ── Games ──────────────────────────────────────────────────────────────────
@app.get("/api/games")
def list_games():
    with get_db() as c:
        rows = c.execute("""SELECT g.*, d.name as deck_name, d.commander as my_commander
            FROM games g LEFT JOIN decks d ON g.my_deck_id = d.id
            ORDER BY g.date DESC, g.id DESC""").fetchall()
        return [dict(r) for r in rows]

@app.post("/api/games", status_code=201)
def create_game(g: GameIn):
    with get_db() as c:
        cur = c.execute("""INSERT INTO games (date,location,my_deck_id,opp1_commander,opp1_colors,opp1_archetype,
            opp2_commander,opp2_colors,opp2_archetype,opp3_commander,opp3_colors,opp3_archetype,
            winner_commander,win_condition,i_won,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (g.date,g.location,g.my_deck_id,g.opp1_commander,g.opp1_colors,g.opp1_archetype,
             g.opp2_commander,g.opp2_colors,g.opp2_archetype,g.opp3_commander,g.opp3_colors,g.opp3_archetype,
             g.winner_commander,g.win_condition,g.i_won,g.notes))
        c.commit(); return {"id": cur.lastrowid, **g.dict()}

@app.put("/api/games/{gid}")
def update_game(gid: int, g: GameIn):
    with get_db() as c:
        c.execute("""UPDATE games SET date=?,location=?,my_deck_id=?,opp1_commander=?,opp1_colors=?,opp1_archetype=?,
            opp2_commander=?,opp2_colors=?,opp2_archetype=?,opp3_commander=?,opp3_colors=?,opp3_archetype=?,
            winner_commander=?,win_condition=?,i_won=?,notes=? WHERE id=?""",
            (g.date,g.location,g.my_deck_id,g.opp1_commander,g.opp1_colors,g.opp1_archetype,
             g.opp2_commander,g.opp2_colors,g.opp2_archetype,g.opp3_commander,g.opp3_colors,g.opp3_archetype,
             g.winner_commander,g.win_condition,g.i_won,g.notes,gid))
        c.commit(); return {"id": gid, **g.dict()}

@app.delete("/api/games/{gid}")
def delete_game(gid: int):
    with get_db() as c:
        c.execute("DELETE FROM games WHERE id=?", (gid,)); c.commit(); return {"deleted": gid}

# ── Stats ──────────────────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats():
    with get_db() as c:
        total = c.execute("SELECT COUNT(*) FROM games").fetchone()[0]
        wins  = c.execute("SELECT COUNT(*) FROM games WHERE i_won=1").fetchone()[0]
        deck_stats = [dict(r) for r in c.execute("""
            SELECT d.id, d.name, d.commander, d.color_identity, d.archetype, d.colors,
                   COUNT(g.id) as games_played,
                   COALESCE(SUM(g.i_won),0) as wins,
                   ROUND(CAST(COALESCE(SUM(g.i_won),0) AS FLOAT)/NULLIF(COUNT(g.id),0)*100,1) as win_pct,
                   MAX(g.date) as last_played
            FROM decks d LEFT JOIN games g ON d.id = g.my_deck_id
            GROUP BY d.id ORDER BY games_played DESC, d.name""").fetchall()]
        win_conds = [dict(r) for r in c.execute("""
            SELECT win_condition, COUNT(*) as count FROM games
            WHERE win_condition IS NOT NULL AND win_condition != ''
            GROUP BY win_condition ORDER BY count DESC LIMIT 8""").fetchall()]
        recent = [dict(r) for r in c.execute("""
            SELECT g.*, d.name as deck_name FROM games g
            LEFT JOIN decks d ON g.my_deck_id = d.id
            ORDER BY g.date DESC, g.id DESC LIMIT 10""").fetchall()]
        return {"total_games":total,"total_wins":wins,
                "win_rate": round(wins/total*100,1) if total else 0,
                "deck_stats":deck_stats,"win_conditions":win_conds,"recent_games":recent}

# ── Opponents ──────────────────────────────────────────────────────────────
@app.get("/api/opponents")
def list_opponents():
    with get_db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM opponents ORDER BY name").fetchall()]

@app.post("/api/opponents", status_code=201)
def create_opponent(o: OpponentIn):
    with get_db() as c:
        cur = c.execute("INSERT INTO opponents (name,commander,colors,archetype,power_level,notes) VALUES (?,?,?,?,?,?)",
            (o.name,o.commander,o.colors,o.archetype,o.power_level,o.notes))
        c.commit(); return {"id": cur.lastrowid, **o.dict()}

@app.delete("/api/opponents/{oid}")
def delete_opponent(oid: int):
    with get_db() as c:
        c.execute("DELETE FROM opponents WHERE id=?", (oid,)); c.commit(); return {"deleted": oid}

# ── Serve frontend ─────────────────────────────────────────────────────────
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(frontend_dir):
    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_frontend(full_path: str):
        return FileResponse(os.path.join(frontend_dir, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), reload=True)
