# ⚔ EDH Vault — Commander Tracker

Mobile-first Commander/EDH tracker. FastAPI backend + SQLite + single-page HTML UI.

---

## 🚀 Run Locally

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload
# Open http://localhost:8000
```

---

## ☁️ Deploy to Render (Free — Recommended)

Render gives you a persistent disk so your database survives restarts.

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "EDH Vault"
gh repo create edh-vault --private --push   # or use github.com
```

### Step 2: Deploy on Render
1. Go to **[render.com](https://render.com)** → Sign up free
2. Click **New → Web Service**
3. Connect your GitHub repo
4. Render auto-detects `render.yaml` and configures everything:
   - Build: `pip install -r requirements.txt`
   - Start: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
   - Persistent disk at `/data` (your DB won't reset on redeploy)
5. Click **Create Web Service** — deploys in ~2 min

### Step 3: Add to your phone home screen
- Open the Render URL in Safari/Chrome on your phone
- **iOS**: Share → "Add to Home Screen"  
- **Android**: Menu → "Add to Home Screen"

It works like a native app!

---

## 📱 Mobile UX Features

- **Bottom navigation bar** — thumb-friendly, stays fixed
- **Bottom sheet modals** — swipe up, tap to dismiss
- **Step wizard for game logging** — guided 4-step flow so you can log quickly mid-session
- **16px font inputs** — prevents iOS auto-zoom on focus
- **safe-area-inset** support — works on iPhones with notches
- **Large tap targets** — minimum 44×44px throughout

---

## 🗂 Structure

```
edh-vault/
├── backend/
│   └── main.py        # FastAPI + SQLite API
├── frontend/
│   └── index.html     # Single-page mobile UI
├── render.yaml        # One-click Render deploy config
└── requirements.txt
```

## 🔧 API Reference

`GET/POST /api/decks` · `PUT/DELETE /api/decks/:id`  
`GET/POST /api/games` · `PUT/DELETE /api/games/:id`  
`GET /api/stats`  
`GET/POST /api/opponents` · `DELETE /api/opponents/:id`

Interactive docs at `/docs` when running locally.
