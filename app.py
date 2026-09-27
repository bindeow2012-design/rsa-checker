from flask import Flask, render_template, request, jsonify
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)

# ==================== Database Setup ====================
DB_PATH = os.environ.get("DB_PATH", "results.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            digits INTEGER,
            D_target INTEGER,
            D_actual REAL,
            p TEXT,
            q TEXT,
            n TEXT,
            cracked INTEGER,
            k INTEGER,
            time_sec REAL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_digits_D ON experiments(digits, D_target)")
    conn.commit()
    conn.close()

# สร้าง DB ตอนเริ่ม
init_db()

# ==================== API: รับข้อมูลจากมือถือ ====================
@app.route("/api/submit", methods=["POST"])
def submit():
    try:
        data = request.get_json()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO experiments 
            (timestamp, source, digits, D_target, D_actual, p, q, n, cracked, k, time_sec)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("timestamp", datetime.now().isoformat()),
            data.get("source", "unknown"),
            data["digits"], data["D_target"], data["D_actual"],
            str(data["p"]), str(data["q"]), str(data["n"]),
            data["cracked"], data["k"], data["time_sec"]
        ))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 400

# ==================== API: ข้อมูลสรุป ====================
@app.route("/api/summary", methods=["GET"])
def summary():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT digits, D_target, COUNT(*), AVG(k), MIN(k), MAX(k)
        FROM experiments
        WHERE cracked = 1
        GROUP BY digits, D_target
        ORDER BY digits, D_target
    """)
    rows = c.fetchall()
    conn.close()
    
    return jsonify([{
        "digits": r[0], "D_target": r[1], "count": r[2],
        "avg_k": round(r[3], 2) if r[3] else 0,
        "min_k": r[4], "max_k": r[5]
    } for r in rows])

# ==================== API: ตรวจความปลอดภัย ====================
@app.route("/api/check", methods=["POST"])
def check_security():
    try:
        data = request.get_json()
        n = int(data["n"])
        D = int(data.get("D", 50))
        digits = len(str(n))
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT digits, D_target, AVG(k)
            FROM experiments
            WHERE cracked = 1 AND digits = ? AND D_target <= ?
            GROUP BY digits, D_target
            ORDER BY D_target DESC
            LIMIT 1
        """, (digits, D))
        row = c.fetchone()
        conn.close()
        
        if not row:
            return jsonify({"status": "unknown", "msg": "ไม่มีข้อมูลอ้างอิงสำหรับค่านี้"})
        
        avg_k = row[2]
        
        if avg_k < 1e3:
            verdict, msg = "danger", f"❌ อันตรายมาก! ใช้แค่ {avg_k:.0f} รอบ"
        elif avg_k < 1e6:
            verdict, msg = "warning", f"⚠️ ความปลอดภัยต่ำ (k ≈ {avg_k:.0f})"
        elif avg_k < 2**40:
            verdict, msg = "moderate", f"🟡 พอใช้ได้ (k ≈ {avg_k:.0f})"
        else:
            verdict, msg = "safe", f"✅ ปลอดภัย (k ≈ {avg_k:.2e})"
        
        return jsonify({
            "status": verdict, "msg": msg,
            "avg_k": avg_k, "digits": digits, "D_used": row[1]
        })
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 400

# ==================== API: นับจำนวนข้อมูล ====================
@app.route("/api/stats", methods=["GET"])
def stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*), COUNT(DISTINCT source) FROM experiments")
    row = c.fetchone()
    conn.close()
    return jsonify({"total_rows": row[0], "sources": row[1]})

# ==================== Pages ====================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)