from flask import Flask, render_template, request, jsonify
import psycopg
from psycopg.rows import dict_row
import os
import math
import time
from datetime import datetime

app = Flask(__name__)

# --- ตั้งค่า Database (ดึงจาก Environment Variable ของ Render) ---
DB_URL = os.environ.get("DATABASE_URL")

def get_db():
    if not DB_URL:
        raise ValueError("ไม่พบ DATABASE_URL ในระบบ กรุณาตั้งค่าใน Render Environment")
    return psycopg.connect(DB_URL, row_factory=dict_row)

def calc_k_theory(n, D_percent):
    return ((D_percent / 100.0) ** 2 * math.sqrt(n)) / 8.0

def assess_security(k_value):
    if k_value < 1e3: 
        return "danger", f"❌ อันตรายมาก! ใช้แค่ {k_value:,.0f} รอบ", 10
    elif k_value < 1e6: 
        return "warning", f"⚠️ ความปลอดภัยต่ำ (k ≈ {k_value:,.0f})", 30
    elif k_value < 2**40: 
        return "moderate", f"🟡 พอใช้ได้ (k ≈ {k_value:,.0f})", 60
    elif k_value < 2**64: 
        return "safe", f"✅ ปลอดภัย (k ≈ {k_value:.2e})", 85
    else: 
        return "very_safe", f"🟢 ปลอดภัยสูงมาก (k ≈ {k_value:.2e})", 100

def fermat_factorize_exact(n, max_iter=200000):
    a = math.isqrt(n)
    if a * a < n: a += 1
    k = 0
    while k < max_iter:
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return (a - b), (a + b), k, True
        a += 1
        k += 1
    return None, None, max_iter, False

def check_weak_keys(n, e):
    weaknesses = []
    digits_n = len(str(n))
    if n % 2 == 0: weaknesses.append("🔴 n เป็นเลขคู่ (p=2) แฮกได้ทันที")
    if math.isqrt(n)**2 == n: weaknesses.append("🔴 n เป็นกำลังสองสมบูรณ์ (p=q) อันตรายมาก")
    if e < 65537: weaknesses.append("🟠 ค่า e ต่ำเกินไป (เสี่ยง Low Public Exponent Attack)")
    if digits_n < 10: weaknesses.append("🟠 n มีขนาดเล็กเกินไปสำหรับการใช้งานจริง (< 10 หลัก)")
    return weaknesses

@app.route("/api/reset_db", methods=["POST"])
def reset_db():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("TRUNCATE TABLE experiments RESTART IDENTITY")
        conn.commit()
        conn.close()
        return jsonify({"status": "ok", "msg": "ล้างฐานข้อมูลสำเร็จ"})
    except Exception as ex:
        return jsonify({"status": "error", "msg": str(ex)}), 500

@app.route("/api/check", methods=["POST"])
def check_security():
    try:
        data = request.get_json()
        n = int(data["n"])
        e = int(data.get("e", 65537))
        D = int(data.get("D", 50))
        
        digits_n = len(str(n))
        digits_pq = (digits_n + 1) // 2
        
        weak_keys = check_weak_keys(n, e)
        p_found, q_found, exact_k, is_exact = fermat_factorize_exact(n)
        
        db_avg_k, db_count = None, 0
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT AVG(k) as avg_k, COUNT(*) as count FROM experiments WHERE cracked=1 AND digits=%s AND D_target=%s", (digits_pq, D))
            row = c.fetchone()
            if row and row["avg_k"]:
                db_avg_k = row["avg_k"]
                db_count = row["count"]
            conn.close()
        except Exception: pass

        k_theory = calc_k_theory(n, D)
        k_final = exact_k if is_exact else k_theory
        verdict, msg, score = assess_security(k_final)
        
        explanations = []
        if is_exact:
            explanations.append({"icon": "🎯", "text": f"แยกตัวประกอบสำเร็จ! p = <b>{p_found}</b>, q = <b>{q_found}</b>"})
            explanations.append({"icon": "⏱️", "text": f"อัลกอริทึมใช้เวลา <b>{exact_k:,} รอบ</b>"})
        else:
            explanations.append({"icon": "📐", "text": f"n ใหญ่เกินกว่าจะคำนวณจริง ใช้สูตร: k ≈ <b>{k_theory:,.0f} รอบ</b>"})
            
        if db_count > 0:
            explanations.append({"icon": "🗄️", "text": f"ข้อมูลอ้างอิง (D={D}%): ค่าเฉลี่ย <b>{db_avg_k:,.0f} รอบ</b> จาก {db_count} ตัวอย่าง"})

        return jsonify({
            "status": verdict, "msg": msg, "score": score,
            "k_final": k_final, "is_exact": is_exact, "p": p_found, "q": q_found,
            "weak_keys": weak_keys, "explanations": explanations
        })
    except Exception as ex:
        return jsonify({"status": "error", "msg": str(ex)}), 500

@app.route("/api/submit", methods=["POST"])
def submit():
    try:
        data = request.get_json()
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO experiments 
            (timestamp, source, digits, D_target, D_actual, p, q, n, e, cracked, k, time_sec) 
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            data.get("timestamp", datetime.now().isoformat()), 
            data.get("source", "unknown"), 
            data["digits"], data["D_target"], data["D_actual"], 
            str(data["p"]), str(data["q"]), str(data["n"]), 
            str(data.get("e", "65537")), 
            data["cracked"], data["k"], data["time_sec"]
        ))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"}), 200
    except Exception as ex:
        return jsonify({"status": "error", "msg": str(ex)}), 400

@app.route("/api/summary")
def summary():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            SELECT digits, D_target AS "D_target", COUNT(*) AS "count", AVG(k) AS "avg_k", MIN(k) AS "min_k", MAX(k) AS "max_k" 
            FROM experiments WHERE cracked=1 AND k > 0
            GROUP BY digits, D_target ORDER BY digits, D_target
        """)
        rows = c.fetchall()
        conn.close()
        return jsonify(rows)
    except Exception:
        return jsonify([])

@app.route("/api/raw_data")
def raw_data():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            SELECT id, n, e, p, q, k, digits, D_target, timestamp 
            FROM experiments ORDER BY id DESC LIMIT 200
        """)
        rows = c.fetchall()
        conn.close()
        return jsonify(rows)
    except Exception:
        return jsonify([])

@app.route("/")
def index(): return render_template("index.html")

@app.route("/dashboard")
def dashboard(): return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
