# -*- coding: utf-8 -*-
"""
RSA Security Checker — Backend
ใช้ทั้งสูตรคณิตศาสตร์และข้อมูลการทดลองเพื่อประเมินความปลอดภัยของ RSA
"""

from flask import Flask, render_template, request, jsonify
import sqlite3
import os
import math
from datetime import datetime

app = Flask(__name__)

# ==================== Config ====================
DB_PATH = os.environ.get("DB_PATH", "results.db")

# เกณฑ์ความปลอดภัย (อ้างอิง NIST 128-bit security)
THRESHOLD_DANGER = 1e3  # < 1,000 รอบ → อันตรายมาก
THRESHOLD_WARNING = 1e6  # < 1 ล้าน → ความปลอดภัยต่ำ
THRESHOLD_MODERATE = 2 ** 40  # < 1.1e12 → พอใช้ได้
THRESHOLD_SAFE = 2 ** 64  # < 1.8e19 → ปลอดภัย


# >= 2^64 → ปลอดภัยสูงมาก


# ==================== Database ====================
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


init_db()


# ==================== Helper: คำนวณ k ด้วยสูตรทฤษฎี ====================
def calc_k_theory(n, D_percent):
    """
    คำนวณจำนวนรอบ Fermat ด้วยสูตรทฤษฎี
    k ≈ (D² × √N) / 8
    โดย D = (q-p)/√N, เก็บในรูปเปอร์เซ็นต์
    """
    D_ratio = D_percent / 100.0
    sqrt_n = math.sqrt(n)
    return (D_ratio ** 2 * sqrt_n) / 8.0


# ==================== Helper: ประเมินความปลอดภัย ====================
def assess_security(k_value):
    """ประเมินความปลอดภัยจากค่า k"""
    if k_value < THRESHOLD_DANGER:
        return "danger", f"❌ อันตรายมาก! ใช้แค่ {k_value:,.0f} รอบ"
    elif k_value < THRESHOLD_WARNING:
        return "warning", f"⚠️ ความปลอดภัยต่ำ (k ≈ {k_value:,.0f})"
    elif k_value < THRESHOLD_MODERATE:
        return "moderate", f"🟡 พอใช้ได้ (k ≈ {k_value:,.0f})"
    elif k_value < THRESHOLD_SAFE:
        return "safe", f"✅ ปลอดภัย (k ≈ {k_value:.2e})"
    else:
        return "very_safe", f"🟢 ปลอดภัยสูงมาก (k ≈ {k_value:.2e})"


# ==================== API: รับข้อมูลจากมือถือ ====================
@app.route("/api/submit", methods=["POST"])
def submit():
    """รับข้อมูล 1 แถวจากมือถือ"""
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
    """ดึงค่าเฉลี่ยตาม (digits, D_target)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT digits, D_target, COUNT(*) as count,
               AVG(k), MIN(k), MAX(k)
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


# ==================== API: นับจำนวนข้อมูล ====================
@app.route("/api/stats", methods=["GET"])
def stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*), COUNT(DISTINCT source) FROM experiments")
    row = c.fetchone()
    conn.close()
    return jsonify({
        "total_rows": row[0] or 0,
        "sources": row[1] or 0
    })


# ==================== API: ตรวจความปลอดภัย (ใช้ได้ทุก n) ====================
@app.route("/api/check", methods=["POST"])
def check_security():
    """
    ตรวจความปลอดภัยของ RSA key
    - ใช้สูตรทฤษฎี k ≈ (D² × √N) / 8 คำนวณได้ทุก n
    - ถ้ามีข้อมูลการทดลองที่ตรง → ใช้ค่าเฉลี่ยจริงเพื่อยืนยัน
    """
    try:
        data = request.get_json()

        # --- รับค่า n ---
        try:
            n = int(data["n"])
        except (ValueError, KeyError):
            return jsonify({"status": "error", "msg": "ค่า n ไม่ถูกต้อง"}), 400

        if n < 4:
            return jsonify({"status": "error", "msg": "n ต้องมากกว่า 3"}), 400

        D = int(data.get("D", 50))
        D = max(0, min(100, D))  # จำกัด 0-100

        digits = len(str(n))

        # ===== 1. คำนวณ k ด้วยสูตรทฤษฎี (ใช้ได้ทุก n) =====
        k_theory = calc_k_theory(n, D)

        # ===== 2. ดึงข้อมูลการทดลองมาเทียบ (ถ้ามี) =====
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # หาข้อมูลที่ตรงกับ digits + D ที่ใกล้ที่สุด
        c.execute("""
            SELECT digits, D_target, AVG(k), COUNT(*), MIN(k), MAX(k)
            FROM experiments
            WHERE cracked = 1 AND digits = ? AND D_target = ?
            GROUP BY digits, D_target
        """, (digits, D))
        row_exact = c.fetchone()

        # ถ้าไม่มีข้อมูล D ตรง ให้หาที่ใกล้ที่สุด
        row_near = None
        if not row_exact:
            c.execute("""
                SELECT digits, D_target, AVG(k), COUNT(*), MIN(k), MAX(k)
                FROM experiments
                WHERE cracked = 1 AND digits = ?
                GROUP BY digits, D_target
                ORDER BY ABS(D_target - ?) ASC
                LIMIT 1
            """, (digits, D))
            row_near = c.fetchone()

        conn.close()

        # ===== 3. เลือกค่า k ที่จะใช้ประเมิน =====
        avg_k_real = None
        count_real = 0
        D_real_used = None
        source_type = "theory"  # หรือ "experiment_exact" หรือ "experiment_near"

        if row_exact:
            avg_k_real = row_exact[2]
            count_real = row_exact[3]
            D_real_used = row_exact[1]
            source_type = "experiment_exact"
        elif row_near:
            avg_k_real = row_near[2]
            count_real = row_near[3]
            D_real_used = row_near[1]
            source_type = "experiment_near"

        # ตัดสินใจว่าจะใช้ค่าไหน:
        # - ถ้ามีข้อมูลการทดลอง D ตรง → ใช้ค่าเฉลี่ยจริง
        # - ถ้ามีข้อมูลใกล้ → ใช้ค่าเฉลี่ยจริง (แต่แจ้งว่า D ต่าง)
        # - ถ้าไม่มี → ใช้สูตรทฤษฎี
        if source_type == "experiment_exact":
            k_use = avg_k_real
            confidence = "สูง"
        elif source_type == "experiment_near":
            k_use = avg_k_real
            confidence = "ปานกลาง"
        else:
            k_use = k_theory
            confidence = "ทฤษฎี"

        # ===== 4. ประเมินความปลอดภัย =====
        verdict, msg = assess_security(k_use)

        # ===== 5. สร้างคำอธิบาย =====
        explanations = []

        if source_type == "experiment_exact":
            explanations.append({
                "icon": "📊",
                "text": f"ข้อมูลอ้างอิงจากการทดลอง {count_real} ครั้ง (D={D_real_used}%)"
            })
            explanations.append({
                "icon": "✅",
                "text": f"k จากการทดลอง ≈ {avg_k_real:,.0f} รอบ"
            })
            explanations.append({
                "icon": "📐",
                "text": f"k จากสูตรทฤษฎี ≈ {k_theory:,.0f} รอบ"
            })
            # เช็คว่าตรงกันไหม
            if avg_k_real > 0:
                diff_pct = abs(avg_k_real - k_theory) / avg_k_real * 100
                if diff_pct < 30:
                    explanations.append({
                        "icon": "🎯",
                        "text": f"สูตรกับผลการทดลองสอดคล้องกัน (ต่าง {diff_pct:.1f}%)"
                    })
                else:
                    explanations.append({
                        "icon": "⚠️",
                        "text": f"สูตรกับผลการทดลองต่างกัน {diff_pct:.1f}% (อาจเกิดจาก sample size น้อย)"
                    })
        elif source_type == "experiment_near":
            explanations.append({
                "icon": "📊",
                "text": f"ใช้ข้อมูล D={D_real_used}% (ใกล้เคียง D={D}% ที่กรอก) จาก {count_real} ครั้ง"
            })
            explanations.append({
                "icon": "📐",
                "text": f"k ≈ {avg_k_real:,.0f} รอบ"
            })
        else:
            explanations.append({
                "icon": "📐",
                "text": f"ใช้สูตรทฤษฎี k ≈ (D² × √N) / 8"
            })
            explanations.append({
                "icon": "🧮",
                "text": f"= ({D}² / 100² × √{n}) / 8 ≈ {k_theory:,.0f} รอบ"
            })
            explanations.append({
                "icon": "💡",
                "text": "n นี้ยังไม่มีในฐานข้อมูล ใช้สูตรคำนวณแทน"
            })

        # ===== 6. ส่งกลับ =====
        return jsonify({
            "status": verdict,
            "msg": msg,
            "k_used": k_use,
            "k_theory": k_theory,
            "k_experiment": avg_k_real,
            "count_real": count_real,
            "D_input": D,
            "D_experiment": D_real_used,
            "digits": digits,
            "source_type": source_type,
            "confidence": confidence,
            "explanations": explanations,
            "n_str": f"{n:,}"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "msg": f"เกิดข้อผิดพลาด: {str(e)}"}), 500


# ==================== Pages ====================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/about")
def about():
    return render_template("about.html")


# ==================== Run ====================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)