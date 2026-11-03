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
    """เชื่อมต่อฐานข้อมูล Supabase"""
    if not DB_URL:
        raise ValueError("ไม่พบ DATABASE_URL ในระบบ กรุณาตั้งค่าใน Render Environment")
    # ใช้ dict_row เพื่อให้ดึงข้อมูลออกมาเป็น Dictionary (มี key ชื่อคอลัมน์) อ่านง่าย
    return psycopg.connect(DB_URL, row_factory=dict_row)

def calc_k_theory(n, D_percent):
    """คำนวณ k จากสูตรทฤษฎี"""
    return ((D_percent / 100.0) ** 2 * math.sqrt(n)) / 8.0

def assess_security(k_value):
    """ประเมินระดับความปลอดภัย"""
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
    """คำนวณและคืนค่า p, q, k จริง (Exact)"""
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
    """ระบบตรวจสอบกุญแจ RSA เบื้องต้น (Weak Key Checker)"""
    weaknesses = []
    digits_n = len(str(n))
    
    if n % 2 == 0:
        weaknesses.append("🔴 n เป็นเลขคู่ (p=2) แฮกได้ทันที")
    if math.isqrt(n)**2 == n:
        weaknesses.append("🔴 n เป็นกำลังสองสมบูรณ์ (p=q) อันตรายมาก")
    if e < 65537:
        weaknesses.append("🟠 ค่า e ต่ำเกินไป (เสี่ยง Low Public Exponent Attack)")
    if digits_n < 10:
        weaknesses.append("🟠 n มีขนาดเล็กเกินไปสำหรับการใช้งานจริง (< 10 หลัก)")
        
    return weaknesses

# ==================== API ROUTES ====================

@app.route("/api/reset_db", methods=["POST"])
def reset_db():
    """ล้างข้อมูลในฐานข้อมูลทั้งหมด"""
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
    """ตรวจสอบความปลอดภัยของ n"""
    try:
        data = request.get_json()
        n = int(data["n"])
        e = int(data.get("e", 65537))
        D = int(data.get("D", 50))
        
        digits_n = len(str(n))
        digits_pq = (digits_n + 1) // 2
        
        # 1. เช็ค Weak Key
        weak_keys = check_weak_keys(n, e)
        
        # 2. คำนวณ Fermat จริง
        p_found, q_found, exact_k, is_exact = fermat_factorize_exact(n)
        
        # 3. ดึงข้อมูลอ้างอิงจาก DB
        db_avg_k = None
        db_count = 0
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT AVG(k) as avg_k, COUNT(*) as count FROM experiments WHERE cracked=1 AND digits=%s AND D_target=%s", (digits_pq, D))
            row = c.fetchone()
            if row and row["avg_k"]:
                db_avg_k = row["avg_k"]
                db_count = row["count"]
            conn.close()
        except Exception as db_err:
            print("DB Error:", db_err)

        k_theory = calc_k_theory(n, D)
        
        # 4. ตัดสินใจใช้ค่าไหน
        k_final = exact_k if is_exact else k_theory
        verdict, msg, score = assess_security(k_final)
        
        # 5. สร้างคำอธิบาย
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
    """รับข้อมูลจาก Colab"""
    try:
        data = request.get_json()
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO experiments 
            (timestamp, source, digits, D_target, D_actual, p, q, n, cracked, k, time_sec) 
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
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
    except Exception as ex:
        return jsonify({"status": "error", "msg": str(ex)}), 400

@app.route("/api/summary")
def summary():
    """ดึงข้อมูลสรุปสำหรับ Dashboard (แก้บั๊ก undefined แล้ว)"""
    try:
        conn = get_db()
        c = conn.cursor()
        # บังคับตั้งชื่อ Alias ให้เป็นตัวพิมพ์ใหญ่ เพื่อให้ JS เรียกใช้ได้ถูก
        # และกรองเฉพาะ k > 0 เพื่อไม่ให้กราฟ Log พัง
        c.execute("""
            SELECT 
                digits, 
                D_target AS "D_target", 
                COUNT(*) AS "count", 
                AVG(k) AS "avg_k", 
                MIN(k) AS "min_k", 
                MAX(k) AS "max_k" 
            FROM experiments 
            WHERE cracked=1 AND k > 0
            GROUP BY digits, D_target 
            ORDER BY digits, D_target
        """)
        rows = c.fetchall()
        conn.close()
        return jsonify(rows)
    except Exception as ex:
        print("Error summary:", ex)
        return jsonify([])

# ==================== PAGES ====================

@app.route("/")
def index(): 
    return render_template("index.html")

@app.route("/dashboard")
def dashboard(): 
    return render_template("dashboard.html")

@app.route("/about")
def about(): 
    return render_template("about.html")

# ==================== RUN ====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
