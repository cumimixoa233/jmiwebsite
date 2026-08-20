import base64
import hashlib
import hmac
import io
import os
import supabase
from datetime import datetime

import streamlit as st

# ============================================================
# JMI VIET NAM - STREAMLIT ONLINE VERSION
# Storage:
#   - Supabase PostgreSQL: users, uploaded_images, contacts
#   - Supabase Storage: uploaded images
#
# If Supabase secrets are not configured, the app falls back to
# local files. This is useful for testing locally, but local data
# on Streamlit Community Cloud is NOT permanent.
# ============================================================

# Thêm CSS ẩn toolbar, footer và các icon bên dưới góc phải
hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stAppToolbar {display: none;}
    [data-testid="stStatusWidget"] {display: none;}
    .viewerBadge_container__1A12q, .viewerBadge_link__1S137, [class^="viewerBadge"] {display: none !important;}
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

st.set_page_config(
    page_title="Công ty TNHH JMI Việt Nam 2026",
    page_icon="🚀",
    layout="wide",
)

# -----------------------------
# CONFIG
# -----------------------------
UPLOAD_BUCKET = "jmi-images"

# Production admin credentials are read ONLY from Streamlit Secrets.
# Never put the real password or Supabase secret key in this file/GitHub.
ADMIN_USERNAME = ""
ADMIN_PASSWORD = ""

# -----------------------------
# SUPABASE CONNECTION
# -----------------------------
supabase = None
cloud_mode = False

try:
    from supabase import create_client

    if "supabase" in st.secrets:
        sb_url = str(st.secrets["supabase"].get("url", "")).strip()
        sb_key = str(st.secrets["supabase"].get("key", "")).strip()

        if sb_url and sb_key:
            supabase = create_client(sb_url, sb_key)
            cloud_mode = True

    if "admin" in st.secrets:
        ADMIN_USERNAME = str(st.secrets["admin"].get("username", "")).strip()
        ADMIN_PASSWORD = str(st.secrets["admin"].get("password", ""))

except Exception as e:
    supabase = None
    cloud_mode = False
    st.error(f"LỖI KẾT NỐI SUPABASE: {e}")


# -----------------------------
# PASSWORD HELPERS
# -----------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        120_000,
    )
    return f"pbkdf2_sha256$120000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False

        new_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(rounds),
        )
        return hmac.compare_digest(new_digest.hex(), digest_hex)
    except Exception:
        return False


# -----------------------------
# LOCAL FALLBACK
# -----------------------------
LOCAL_USERS_FILE = "users.json"
LOCAL_UPLOAD_DIR = "uploads"

os.makedirs(LOCAL_UPLOAD_DIR, exist_ok=True)


def local_load_users():
    import json

    if not os.path.exists(LOCAL_USERS_FILE):
        data = {}
        with open(LOCAL_USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return data

    try:
        with open(LOCAL_USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Compatibility with the old {"admin": "123456"} format.
        changed = False
        for username, value in list(data.items()):
            if isinstance(value, str):
                data[username] = {
                    "password": hash_password(value),
                    "role": "user",
                }
                changed = True

        if changed:
            with open(LOCAL_USERS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)

        return data
    except Exception:
        return {}


def local_save_users(data):
    import json

    with open(LOCAL_USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


# -----------------------------
# USER FUNCTIONS
# -----------------------------
def get_user(username):
    username = username.strip()

    if not cloud_mode:
        users = local_load_users()
        user = users.get(username)
        if not user:
            return None

        if isinstance(user, str):
            return {"username": username, "password": user, "role": "user"}

        return {
            "username": username,
            "password": user.get("password", ""),
            "role": user.get("role", "user"),
        }

    try:
        result = (
            supabase.table("users")
            .select("username,password_hash,role")
            .eq("username", username)
            .limit(1)
            .execute()
        )
        if result.data:
            row = result.data[0]
            return {
                "username": row["username"],
                "password": row["password_hash"],
                "role": row.get("role", "user"),
            }
    except Exception as e:
        st.error(f"Lỗi kết nối cơ sở dữ liệu: {e}")

    return None


def create_user(username, password, role="user"):
    username = username.strip()

    if not username or not password:
        return False, "Vui lòng nhập đầy đủ tài khoản và mật khẩu."

    if get_user(username):
        return False, "Tài khoản đã tồn tại."

    password_hash = hash_password(password)

    if not cloud_mode:
        users = local_load_users()
        users[username] = {
            "password": password_hash,
            "role": role,
        }
        local_save_users(users)
        return True, "Đăng ký thành công."

    try:
        supabase.table("users").insert(
            {
                "username": username,
                "password_hash": password_hash,
                "role": role,
            }
        ).execute()
        return True, "Đăng ký thành công."
    except Exception as e:
        return False, f"Không thể tạo tài khoản: {e}"


# -----------------------------
# FIRST ADMIN INITIALIZATION
# -----------------------------
def ensure_admin_account():
    """Create/repair the first Admin account from Streamlit Secrets."""
    if not cloud_mode or not ADMIN_USERNAME or not ADMIN_PASSWORD:
        return

    if len(ADMIN_PASSWORD) < 8:
        return

    try:
        result = (
            supabase.table("users")
            .select("id,username,password_hash,role")
            .eq("username", ADMIN_USERNAME)
            .limit(1)
            .execute()
        )

        if not result.data:
            supabase.table("users").insert({
                "username": ADMIN_USERNAME,
                "password_hash": hash_password(ADMIN_PASSWORD),
                "role": "admin",
            }).execute()
            return

        row = result.data[0]
        updates = {}

        if row.get("role") != "admin":
            updates["role"] = "admin"

        stored = row.get("password_hash", "")
        if not stored or not verify_password(ADMIN_PASSWORD, stored):
            updates["password_hash"] = hash_password(ADMIN_PASSWORD)

        if updates:
            supabase.table("users").update(updates).eq("id", row["id"]).execute()

    except Exception as e:
        st.error(f"Không thể khởi tạo tài khoản quản trị: {e}")


ensure_admin_account()


# -----------------------------
# IMAGE FUNCTIONS
# -----------------------------
def list_images():
    """Return [(display_name, storage_path, bytes)] for banner images."""
    result = []

    if cloud_mode:
        try:
            rows = (
                supabase.table("uploaded_images")
                .select("file_name,storage_path")
                .order("created_at", desc=False)
                .execute()
            )

            for row in rows.data or []:
                path = row["storage_path"]
                try:
                    data = supabase.storage.from_(UPLOAD_BUCKET).download(path)
                    result.append((row["file_name"], path, data))
                except Exception:
                    pass

            return result
        except Exception:
            return result

    if not os.path.isdir(LOCAL_UPLOAD_DIR):
        return result

    allowed = (".jpg", ".png", ".jpeg", ".webp")
    for name in sorted(os.listdir(LOCAL_UPLOAD_DIR)):
        if name.lower().endswith(allowed):
            path = os.path.join(LOCAL_UPLOAD_DIR, name)
            try:
                with open(path, "rb") as f:
                    result.append((name, path, f.read()))
            except OSError:
                pass

    return result


def upload_image(uploaded_file):
    file_name = os.path.basename(uploaded_file.name)
    ext = os.path.splitext(file_name)[1].lower()

    if ext not in (".jpg", ".png", ".jpeg", ".webp"):
        return False, "Định dạng ảnh không được hỗ trợ."

    data = uploaded_file.getvalue()

    if cloud_mode:
        try:
            # Make storage path unique while preserving the original name.
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            storage_path = f"{stamp}_{file_name}"

            supabase.storage.from_(UPLOAD_BUCKET).upload(
                storage_path,
                data,
                file_options={
                    "content-type": uploaded_file.type or "application/octet-stream",
                    "upsert": "false",
                },
            )

            supabase.table("uploaded_images").insert(
                {
                    "file_name": file_name,
                    "storage_path": storage_path,
                }
            ).execute()

            return True, "Upload ảnh thành công."
        except Exception as e:
            return False, f"Upload lên cloud thất bại: {e}"

    try:
        path = os.path.join(LOCAL_UPLOAD_DIR, file_name)
        with open(path, "wb") as f:
            f.write(data)
        return True, "Upload ảnh thành công."
    except OSError as e:
        return False, f"Không thể lưu ảnh: {e}"


def delete_image(file_name, storage_path):
    if cloud_mode:
        try:
            supabase.storage.from_(UPLOAD_BUCKET).remove([storage_path])
            supabase.table("uploaded_images").delete().eq(
                "storage_path", storage_path
            ).execute()
            return True, "Đã xóa ảnh."
        except Exception as e:
            return False, f"Không thể xóa ảnh: {e}"

    try:
        if os.path.exists(storage_path):
            os.remove(storage_path)
        return True, "Đã xóa ảnh."
    except OSError as e:
        return False, f"Không thể xóa ảnh: {e}"


# -----------------------------
# CONTACT
# -----------------------------
def save_contact(name, email, message):
    if cloud_mode:
        try:
            supabase.table("contacts").insert(
                {
                    "name": name.strip(),
                    "email": email.strip(),
                    "message": message.strip(),
                }
            ).execute()
            return True
        except Exception as e:
            st.error(f"Không thể gửi thông tin: {e}")
            return False

    # Local fallback: append to a CSV-like text file.
    try:
        with open("contacts.txt", "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.now().isoformat()}\t"
                f"{name.strip()}\t{email.strip()}\t{message.strip()}\n"
            )
        return True
    except OSError:
        return False


# -----------------------------
# BANNER
# -----------------------------
def banner_image():
    images = list_images()

    if not images:
        st.info("Chưa có ảnh quảng cáo. Đăng nhập quản trị để upload ảnh.")
        return

    slides = []

    for file_name, _, data in images:
        encoded = base64.b64encode(data).decode("utf-8")
        ext = os.path.splitext(file_name)[1].lower()
        mime = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".webp": "image/webp",
        }.get(ext, "application/octet-stream")
        slides.append(
            f'<img class="slide" src="data:{mime};base64,{encoded}">'
        )

    delays = []
    for index in range(len(slides)):
        delays.append(
            f".slide:nth-child({index + 1}){{animation-delay:{index * 7}s;}}"
        )

    html = f"""
    <style>
    .banner {{
        width:100%;
        height:220px;
        overflow:hidden;
        position:relative;
        border-radius:12px;
    }}

    .slide {{
        position:absolute;
        height:180px;
        max-width:80%;
        object-fit:contain;
        top:20px;
        right:-40%;
        animation: move {max(20, len(slides) * 7)}s linear infinite;
    }}

    {''.join(delays)}

    @keyframes move {{
        0%   {{ right:-40%; }}
        60%  {{ right:110%; }}
        100% {{ right:110%; }}
    }}
    </style>

    <div class="banner">
        {''.join(slides)}
    </div>
    """

    st.components.v1.html(html, height=250)


# -----------------------------
# SESSION
# -----------------------------
if "login" not in st.session_state:
    st.session_state.login = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "role" not in st.session_state:
    st.session_state.role = ""

if "show_login" not in st.session_state:
    st.session_state.show_login = False

if "show_register" not in st.session_state:
    st.session_state.show_register = False


# -----------------------------
# CSS
# -----------------------------
st.markdown(
    """
    <style>
    .stButton>button {
        border-radius:20px;
        background:#007bff;
        color:white;
        padding:10px 24px;
    }

    .hero-text {
        font-size:50px;
        font-weight:800;
        text-align:center;
    }

    .sub-text {
        font-size:20px;
        text-align:center;
        color:#666;
    }

    .card {
        padding:20px;
        border-radius:15px;
        background:white;
        box-shadow:0 4px 6px rgba(0,0,0,.1);
        text-align:center;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# -----------------------------
# ONLINE CONFIG CHECK
# -----------------------------
if not cloud_mode:
    st.warning(
        "Website chưa kết nối Supabase. Khi deploy online, hãy cấu hình "
        "Streamlit Secrets gồm [supabase] và [admin]."
    )
elif not ADMIN_USERNAME or not ADMIN_PASSWORD:
    st.warning(
        "Đã kết nối Supabase nhưng chưa cấu hình [admin]. "
        "Hãy thêm username/password Admin trong Streamlit Secrets."
    )
elif len(ADMIN_PASSWORD) < 8:
    st.warning("Mật khẩu Admin trong Secrets phải có ít nhất 8 ký tự.")


# -----------------------------
# HEADER
# -----------------------------
c1, c2, c3 = st.columns([6, 1, 1])

with c1:
    st.title("🚀 CÔNG TY TNHH JMI VIỆT NAM")

with c2:
    if not st.session_state.login:
        if st.button("🔐 Đăng nhập"):
            st.session_state.show_login = True
            st.session_state.show_register = False
            st.rerun()

with c3:
    if not st.session_state.login:
        if st.button("📝 Đăng ký"):
            st.session_state.show_register = True
            st.session_state.show_login = False
            st.rerun()


# -----------------------------
# LOGIN
# -----------------------------
if st.session_state.show_login and not st.session_state.login:
    st.subheader("🔐 Đăng nhập")

    with st.form("login_form"):
        user = st.text_input("Tài khoản")
        pw = st.text_input("Mật khẩu", type="password")
        login = st.form_submit_button("Đăng nhập")

    if login:
        account = get_user(user)

        if account and verify_password(pw, account["password"]):
            st.session_state.login = True
            st.session_state.username = account["username"]
            st.session_state.role = account["role"]
            st.session_state.show_login = False
            st.session_state.show_register = False
            st.success("Đăng nhập thành công.")
            st.rerun()
        else:
            st.error("Sai tài khoản hoặc mật khẩu.")


# -----------------------------
# REGISTER
# -----------------------------
if st.session_state.show_register and not st.session_state.login:
    st.subheader("📝 Đăng ký")

    with st.form("register_form"):
        new_user = st.text_input("Tài khoản mới")
        new_pw = st.text_input("Mật khẩu mới", type="password")
        new_pw2 = st.text_input("Nhập lại mật khẩu", type="password")
        register = st.form_submit_button("Tạo tài khoản")

    if register:
        if new_pw != new_pw2:
            st.error("Mật khẩu nhập lại không khớp.")
        elif len(new_pw) < 6:
            st.error("Mật khẩu phải có ít nhất 6 ký tự.")
        else:
            ok, message = create_user(new_user, new_pw, "user")
            if ok:
                st.success(message)
                st.session_state.show_register = False
                st.session_state.show_login = True
                st.rerun()
            else:
                st.error(message)


# -----------------------------
# ADMIN UPLOAD
# -----------------------------
if st.session_state.login and st.session_state.role == "admin":
    st.divider()

    col1, col2 = st.columns([6, 1])

    with col1:
        st.subheader("📷 Quản trị Upload ảnh")
        st.caption(
            f"Đang đăng nhập: {st.session_state.username} | "
            f"Chế độ lưu trữ: {'☁️ Supabase Cloud' if cloud_mode else '💻 Local (chỉ test)'}"
        )

    with col2:
        if st.button("🚪 Đăng xuất"):
            st.session_state.login = False
            st.session_state.username = ""
            st.session_state.role = ""
            st.session_state.show_login = False
            st.session_state.show_register = False
            st.rerun()

    uploaded = st.file_uploader(
        "Chọn ảnh quảng cáo",
        type=["jpg", "png", "jpeg", "webp"],
    )

    if uploaded:
        if st.button("⬆️ Upload ảnh", key="upload_button"):
            ok, message = upload_image(uploaded)
            if ok:
                st.success(message)
                st.rerun()
            else:
                st.error(message)

    images = list_images()

    if images:
        st.write("### Danh sách ảnh")

        for index, (file_name, storage_path, data) in enumerate(images):
            col_img, col_name, col_del = st.columns([3, 5, 1])

            with col_img:
                st.image(data, width=180)

            with col_name:
                st.write(file_name)

            with col_del:
                if st.button("🗑️", key=f"delete_{index}"):
                    ok, message = delete_image(file_name, storage_path)
                    if ok:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)


# -----------------------------
# GENERAL LOGOUT
# -----------------------------
if st.session_state.login and st.session_state.role != "admin":
    if st.button("🚪 Đăng xuất", key="logout_user"):
        st.session_state.login = False
        st.session_state.username = ""
        st.session_state.role = ""
        st.session_state.show_login = False
        st.session_state.show_register = False
        st.rerun()


# -----------------------------
# MAIN WEBSITE
# -----------------------------
st.markdown(
    '<p class="hero-text">Kiến tạo tương lai bằng sản phẩm chất lượng</p>',
    unsafe_allow_html=True,
)

st.markdown(
    '<p class="sub-text">Chúng tôi cung cấp giải pháp Khay nhựa hàng đầu cho doanh nghiệp Việt Nam và nước ngoài.</p>',
    unsafe_allow_html=True,
)


if os.path.exists("team_photo.jpg"):
    st.image(
        "team_photo.jpg",
        use_container_width=True,
        caption="Đội ngũ cán bộ CNV JMI Việt Nam",
    )


st.header("Ảnh quảng cáo")
banner_image()

st.divider()

st.header("🎯 Tại sao chọn chúng tôi?")

a, b, c = st.columns(3)

with a:
    st.markdown(
        '<div class="card"><h3>Sáng tạo</h3>'
        '<p>Luôn dẫn đầu xu hướng công nghệ mới nhất 2026.</p></div>',
        unsafe_allow_html=True,
    )

with b:
    st.markdown(
        '<div class="card"><h3>Tận tâm</h3>'
        '<p>Hỗ trợ khách hàng 24/7.</p></div>',
        unsafe_allow_html=True,
    )

with c:
    st.markdown(
        '<div class="card"><h3>Hiệu quả</h3>'
        '<p>Tối ưu quy trình sản xuất.</p></div>',
        unsafe_allow_html=True,
    )


st.header("🛠 Dịch vụ mũi nhọn")

t1, t2, t3 = st.tabs(
    ["Phát triển Khuôn", "Mẫu Nhựa PET", "Tư vấn thiết kế"]
)

with t1:
    st.write("Xây dựng sản phẩm chất lượng.")

with t2:
    st.write("Triển khai thiết bị tiên tiến.")

with t3:
    st.write("Tư vấn chiến lược.")


st.header("📩 Liên hệ hợp tác")

with st.form("contact"):
    name = st.text_input("Họ và tên")
    email = st.text_input("Email")
    msg = st.text_area("Yêu cầu")

    if st.form_submit_button("Gửi"):
        if not name or not email or not msg:
            st.warning("Vui lòng nhập đầy đủ thông tin.")
        elif save_contact(name, email, msg):
            st.success("Đã gửi thông tin. Cảm ơn bạn!")
        else:
            st.error("Không thể gửi thông tin.")


st.markdown(
    "<br><hr><center>© 2026 JMI Solutions</center>",
    unsafe_allow_html=True,
)
