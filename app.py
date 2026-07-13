"""
用户信息管理平台 - 登录 + 注册 + 搜索 + 头像上传
"""
import os
import secrets
import time
import logging
import sqlite3
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    abort,
    url_for,
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# 日志配置
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("app.log", encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flask 应用初始化
# ---------------------------------------------------------------------------
app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32),
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
)

# ---------------------------------------------------------------------------
# 数据库初始化
# ---------------------------------------------------------------------------
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")

# 上传目录
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")


def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    logger.info("数据库初始化完成: %s", DB_PATH)
    logger.info("上传目录: %s", UPLOAD_DIR)


# ---------------------------------------------------------------------------
# 用户数据库（内存）
# ---------------------------------------------------------------------------
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password_hash": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# ---------------------------------------------------------------------------
# 登录频率限制
# ---------------------------------------------------------------------------
LOGIN_LIMIT_WINDOW = 60
LOGIN_LIMIT_MAX_ATTEMPTS = 5
_login_attempts: dict[str, list[float]] = {}


def _check_login_rate_limit(ip: str) -> bool:
    now = time.time()
    records = _login_attempts.get(ip, [])
    records = [t for t in records if now - t < LOGIN_LIMIT_WINDOW]
    if len(records) >= LOGIN_LIMIT_MAX_ATTEMPTS:
        return False
    records.append(now)
    _login_attempts[ip] = records
    return True


# ---------------------------------------------------------------------------
# CSRF 保护
# ---------------------------------------------------------------------------
def _generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(16)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = _generate_csrf_token


def _validate_csrf() -> None:
    token = request.form.get("_csrf_token", "")
    if not token or not secrets.compare_digest(token, session.get("_csrf_token", "")):
        abort(400, "CSRF 验证失败，请刷新页面重试。")


def _sanitize_username(raw: str) -> str:
    import re
    cleaned = re.sub(r"[^\w\-一-鿿]", "", raw.strip())
    return cleaned[:32]


def _get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# 路由 —— 首页
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    username = session.get("username")
    user = USERS.get(username) if username else None

    safe_user = None
    if user:
        safe_user = {
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "phone": user["phone"],
            "balance": user["balance"],
        }

    search_results = None
    keyword = request.args.get("keyword", "")
    if keyword:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print("=" * 60)
        print(f"[SQL] 执行查询: {sql}")
        print("=" * 60)
        logger.info("搜索SQL: %s", sql)
        try:
            c.execute(sql)
            rows = c.fetchall()
            search_results = [{"id": r[0], "username": r[1], "email": r[2], "phone": r[3]} for r in rows]
        except Exception as e:
            print(f"[SQL] 查询出错: {e}")
            search_results = []
        conn.close()

    # 获取当前登录用户的头像文件名
    avatar_filename = None
    if username:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT avatar FROM users WHERE username=?", (username,))
            row = c.fetchone()
            if row and row[0]:
                avatar_filename = row[0]
        except Exception:
            pass
        conn.close()

    return render_template(
        "index.html",
        user=safe_user,
        search_results=search_results,
        keyword=keyword,
        avatar_filename=avatar_filename,
    )


# ---------------------------------------------------------------------------
# 路由 —— 登录
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        client_ip = _get_client_ip()
        if not _check_login_rate_limit(client_ip):
            logger.warning("登录频率超限: IP=%s", client_ip)
            return render_template("login.html", error="登录尝试过于频繁，请稍后再试。")

        _validate_csrf()

        raw_username = request.form.get("username", "")
        raw_password = request.form.get("password", "")
        username = _sanitize_username(raw_username)

        if not username or not raw_password:
            logger.info("登录失败（空输入）: IP=%s", client_ip)
            return render_template("login.html", error="用户名或密码不正确。")

        user = USERS.get(username)
        if user is None:
            logger.info("登录失败（用户不存在）: username=%s, IP=%s", username, client_ip)
            return render_template("login.html", error="用户名或密码不正确。")

        if not check_password_hash(user["password_hash"], raw_password):
            logger.info("登录失败（密码错误）: username=%s, IP=%s", username, client_ip)
            return render_template("login.html", error="用户名或密码不正确。")

        session.permanent = True
        session["username"] = username
        session.sid = secrets.token_hex(16)

        logger.info("登录成功: username=%s, IP=%s", username, client_ip)
        return redirect("/")

    return render_template("login.html")


# ---------------------------------------------------------------------------
# 路由 —— 注册
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print("=" * 60)
        print(f"[SQL] 执行插入: {sql}")
        print("=" * 60)
        logger.info("注册SQL: %s", sql)
        try:
            c.execute(sql)
            conn.commit()
            logger.info("注册成功: username=%s", username)
            conn.close()
            return render_template("login.html", error="注册成功，请登录")
        except Exception as e:
            print(f"[SQL] 插入出错: {e}")
            conn.close()
            return render_template("register.html", error=f"注册失败: {e}")

    return render_template("register.html")


# ---------------------------------------------------------------------------
# 路由 —— 上传头像
# ---------------------------------------------------------------------------
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    uploaded_file_url = None
    filename = None

    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename:
            filename = file.filename
            save_path = os.path.join(UPLOAD_DIR, filename)
            file.save(save_path)
            uploaded_file_url = url_for("static", filename=f"uploads/{filename}")
            logger.info("文件上传成功: username=%s, filename=%s", session["username"], filename)
        else:
            return render_template("upload.html", error="请选择一个文件")

    return render_template("upload.html", uploaded_file_url=uploaded_file_url, filename=filename)


# ---------------------------------------------------------------------------
# 路由 —— 动态页面加载（含路径穿越漏洞）
# ---------------------------------------------------------------------------
PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")


@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    if not name:
        return render_template("index.html", page_content="请输入页面名称")

    # 直接拼接用户输入到路径中（不做任何过滤，允许 ../ 穿越）
    file_path = os.path.join(PAGES_DIR, name)
    content = None

    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            content = "读取文件失败"
    else:
        # 尝试加上 .html 后缀
        file_path_html = file_path + ".html"
        if os.path.exists(file_path_html):
            try:
                with open(file_path_html, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                content = "读取文件失败"
        else:
            content = "页面不存在"

    return render_template("index.html", page_content=content)


# ---------------------------------------------------------------------------
# 路由 —— 登出
# ---------------------------------------------------------------------------
@app.route("/logout")
def logout():
    username = session.get("username", "anonymous")
    logger.info("登出: username=%s", username)
    session.clear()
    return redirect("/")


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    logger.info("Flask 启动: debug=%s, host=0.0.0.0:5000", debug_mode)
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
