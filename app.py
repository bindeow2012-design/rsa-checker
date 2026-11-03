from flask import Flask, render_template, request, jsonify
import sqlite3
import os
import math
import time
from datetime import datetime

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "results.db")

# เกณฑ์ความปลอดภัย
THRESHOLD_DANGER   = 1e3
THRESHOLD_WARNING  = 1e6
THRESHOLD_MODERATE = 2**40
THRESHOLD_SAFE     = 2**64

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source TEXT, digits INTEGER,
            D_target INTEGER, D_actual REAL, p TEXT, q TEXT,
            n TEXT, cracked INTEGER, k INTEGER, time_sec REAL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def calc_k_theory(n, D_percent):
    D_ratio = D_percent / 100.0
    return (D_ratio ** 2 * math.sqrt(n)) / 8.0

def assess_security(k_value):
    if k_value < THRESHOLD_DANGER:
        return "danger", f"❌ อันตรายมาก! ใช้แค่ {k_value:,.0f} รอบ", 10
    elif k_value < THRESHOLD_WARNING:
        return "warning", f"⚠️ ความปลอดภัยต่ำ (k ≈ {k_value:,.0f})", 30
    elif k_value < THRESHOLD_MODERATE:
        return "moderate", f"🟡 พอใช้ได้ (k ≈ {k_value:,.0f})", 60
    elif k_value < THRESHOLD_SAFE:
        return "safe", f"✅ ปลอดภัย (k ≈ {k_value:.2e})", 85
    else:
        return "very_safe", f"🟢 ปลอดภัยสูงมาก (k ≈ {k_value:.2e})", 100

# 🚀 เพิ่มฟังก์ชันคำนวณหาค่า k จริงๆ (Exact) สำหรับ n ที่ส่งมา
def fermat_factorize_exact(n, max_iter=200000):
    """พยายามแยกตัวประกอบ n จริงๆ ถ้าทำได้จะคืนค่า k จริง"""
    start_t = time.time()
    a = math.isqrt(n)
    if a * a < n: a += 1
    k = 0
    while k < max_iter:
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return k, True # เจอแล้ว คืนค่า k จริง
        a += 1
        k += 1
    return max_iter, False # ถ้าเกิน limit ถือว่าแยกไม่ได้(ในเวลาอันสั้น)

@app.route("/api/reset_db", methods=["POST"])
def reset_db():
    """ล้างข้อมูลทั้งหมดในตาราง"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM experiments")
        conn.commit()
        conn.close()
        return jsonify({"status": "ok", "msg": "ล้างฐานข้อมูลสำเร็จ"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route("/api/check", methods=["POST"])
def check_security():
    try:
        data = request.get_json()
        n = int(data["n"])
        D = int(data.get("D", 50))
        digits_n = len(str(n))
        digits_pq = (digits_n + 1) // 2
        
        # 1. ลองคำนวณจริงก่อน (ถ้า n ไม่ใหญ่เกินไป)
        exact_k = None
        is_exact = False
        
        # ถ้า n ไม่เกิน 16 หลัก ให้ลองคำนวณจริงบน Server เลย (ใช้เวลาไม่ถึง 1 วิ)
        if digits_n <= 16:
            exact_k, is_exact = fermat_factorize_exact(n)
        
        # 2. ดึงข้อมูลจาก DB (เพื่อใช้เป็นข้อมูลอ้างอิง)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT AVG(k), COUNT(*) FROM experiments WHERE cracked=1 AND digits=? AND D_target=?", (digits_pq, D))
        row = c.fetchone()
        db_avg_k = row[0] if row[0] else None
        db_count = row[1] if row[1] else 0
        conn.close()

        k_theory = calc_k_theory(n, D)
        
        # 3. ตัดสินใจใช้ค่าไหนประเมินผล
        if is_exact:
            # ถ้าคำนวณจริงได้ ให้ใช้ค่าจริงเท่านั้น (แม่นยำ 100%)
            k_final = exact_k
            source_type = "exact"
        else:
            # ถ้าคำนวณจริงไม่ได้ (เลขใหญ่มาก) ให้ใช้ทฤษฎี
            k_final = k_theory
            source_type = "theory"

        verdict, msg, score = assess_security(k_final)
        
        # 4. สร้างคำอธิบาย
        explanations = []
        
        if is_exact:
            explanations.append({"icon": "🎯", "text": f"ระบบได้ทำการรันอัลกอริทึมแฟร์มาต์กับ n นี้จริงๆ และใช้เวลา <b>{exact_k:,} รอบ</b> ในการแยกตัวประกอบ"})
        else:
            explanations.append({"icon": "📐", "text": f"n มีขนาดใหญ่เกินกว่าจะคำนวณจริงได้ทันที ระบบจึงใช้สูตรทฤษฎี: k ≈ (D² × √N) / 8 = <b>{k_theory:,.0f} รอบ</b>"})
            
        if db_count > 0:
            explanations.append({"icon": "🗄️", "text": f"ข้อมูลอ้างอิงในฐานข้อมูล: กลุ่มเลข {digits_pq} หลัก, D={D}% มีค่าเฉลี่ยอยู่ที่ <b>{db_avg_k:,.0f} รอบ</b> (จาก {db_count} ตัวอย่าง)"})

        return jsonify({
            "status": verdict, "msg": msg, "score": score,
            "k_final": k_final, "is_exact": is_exact,
            "k_theory": k_theory, "k_exact": exact_k,
            "db_avg_k": db_avg_k, "db_count": db_count,
            "digits_n": digits_n, "explanations": explanations
        })
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route("/api/submit", methods=["POST"])
def submit():
    # (โค้ดเหมือนเดิม)
    try:
        data = request.get_json()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO experiments (timestamp, source, digits, D_target, D_actual, p, q, n, cracked, k, time_sec) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (data.get("timestamp"), data.get("source"), data["digits"], data["D_target"], data["D_actual"], str(data["p"]), str(data["q"]), str(data["n"]), data["cracked"], data["k"], data["time_sec"]))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 400

@app.route("/api/summary")
def summary():
    # (โค้ดเหมือนเดิม)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT digits, D_target, COUNT(*), AVG(k), MIN(k), MAX(k) FROM experiments WHERE cracked=1 GROUP BY digits, D_target ORDER BY digits, D_target")
    rows = c.fetchall()
    conn.close()
    return jsonify([{"digits": r[0], "D_target": r[1], "count": r[2], "avg_k": r[3], "min_k": r[4], "max_k": r[5]} for r in rows])

@app.route("/")
def index(): return render_template("index.html")

@app.route("/dashboard")
def dashboard(): return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
