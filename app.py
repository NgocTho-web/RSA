
import streamlit as st

from rsa_core import (
    generate_keypair,
    encrypt,
    decrypt,
    parse_ciphertext,
    ciphertext_to_string
)


# ==========================================
# 1. CẤU HÌNH GIAO DIỆN
# ==========================================
st.set_page_config(
    page_title="RSA SecureShare",
    page_icon="🔐",
    layout="wide"
)

# Lưu bản mã trong phiên làm việc
if "sent_ciphertext" not in st.session_state:
    st.session_state.sent_ciphertext = ""

if "public_key" not in st.session_state:
    st.session_state.public_key = None

if "private_key" not in st.session_state:
    st.session_state.private_key = None


# ==========================================
# 2. THANH ĐIỀU HƯỚNG
# ==========================================
st.sidebar.title("🔐 RSA SecureShare")

page = st.sidebar.radio(
    "Chọn trang",
    [
        "Trang 1 - Tạo khóa RSA",
        "Trang 2 - Người A gửi thông điệp",
        "Trang 3 - Người B giải mã"
    ]
)

st.sidebar.divider()
st.sidebar.info(
    "RSA được tự code bằng Python. "
    "Không sử dụng thư viện mật mã."
)


# ==========================================
# TRANG 1: TẠO CẶP KHÓA RSA
# ==========================================
if page == "Trang 1 - Tạo khóa RSA":

    st.title("🔑 Trang 1 – Tạo cặp khóa RSA")

    st.write(
        "Nhập hai số nguyên tố p và q. "
        "Hệ thống sẽ tự tính e, d và tạo cặp khóa."
    )

    with st.form("key_form"):

        p = st.number_input(
            "Nhập số nguyên tố p",
            min_value=2,
            value=None,
            step=1
        )

        q = st.number_input(
            "Nhập số nguyên tố q",
            min_value=2,
            value=None,
            step=1
        )

        create_key = st.form_submit_button(
            "🔑 Tạo cặp khóa RSA",
            use_container_width=True
        )

    if create_key:

        if p is None or q is None:
            st.error("Vui lòng nhập đầy đủ p và q.")

        else:
            try:
                public_key, private_key = generate_keypair(
                    int(p), int(q)
                )

                st.session_state.public_key = public_key
                st.session_state.private_key = private_key

                # Xóa thông điệp cũ khi tạo khóa mới
                st.session_state.sent_ciphertext = ""

                st.success("Tạo cặp khóa RSA thành công!")

            except ValueError as error:
                st.error(str(error))

    if st.session_state.public_key is not None:

        st.subheader("🔓 Public Key")

        e, n = st.session_state.public_key

        st.code(f"e = {e}\nn = {n}", language="text")

        st.caption(
            "Chia sẻ Public Key này cho người A."
        )

    if st.session_state.private_key is not None:

        st.subheader("🔐 Private Key")

        d, n = st.session_state.private_key

        st.code(f"d = {d}\nn = {n}", language="text")

        st.warning(
            "Private Key chỉ dành cho người B. "
            "Không chia sẻ khóa này cho người A."
        )


# ==========================================
# TRANG 2: NGƯỜI A MÃ HÓA VÀ GỬI
# ==========================================
elif page == "Trang 2 - Người A gửi thông điệp":

    st.title("📤 Trang 2 – Người A gửi thông điệp")

    st.write(
        "Người A nhập Public Key của B và thông điệp "
        "cần gửi. Hệ thống mã hóa bằng RSA."
    )

    with st.form("encrypt_form"):

        st.subheader("🔓 Nhập Public Key")

        e_input = st.text_input(
            "Nhập e",
            placeholder="Ví dụ: 7"
        )

        n_input = st.text_input(
            "Nhập n",
            placeholder="Ví dụ: 4819"
        )

        st.subheader("✉️ Thông điệp")

        message = st.text_area(
            "Nhập nội dung cần gửi",
            placeholder="Xin chào B!",
            height=150
        )

        send_button = st.form_submit_button(
            "🔐 Mã hóa và gửi",
            use_container_width=True
        )

    if send_button:

        if not e_input.strip() or not n_input.strip():
            st.error("Vui lòng nhập đầy đủ Public Key.")

        elif not message.strip():
            st.error("Vui lòng nhập thông điệp.")

        else:
            try:
                e = int(e_input)
                n = int(n_input)

                public_key = (e, n)

                ciphertext = encrypt(
                    message,
                    public_key
                )

                ciphertext_text = ciphertext_to_string(
                    ciphertext
                )

                st.session_state.sent_ciphertext = (
                    ciphertext_text
                )

                st.success(
                    "Mã hóa và gửi thông điệp thành công!"
                )

            except ValueError as error:
                st.error(str(error))

    if st.session_state.sent_ciphertext:

        st.subheader("📦 Bản mã đã gửi")

        st.code(
            st.session_state.sent_ciphertext,
            language="text"
        )

        st.info(
            "Thông điệp đã được chuyển sang Trang 3. "
            "Người B cần nhập Private Key để giải mã."
        )


# ==========================================
# TRANG 3: NGƯỜI B GIẢI MÃ
# ==========================================
elif page == "Trang 3 - Người B giải mã":

    st.title("📥 Trang 3 – Người B giải mã")

    st.write(
        "Người B nhập Private Key và bản mã "
        "để khôi phục thông điệp gốc."
    )

    if st.session_state.sent_ciphertext:

        st.success("Đã nhận được thông điệp từ A.")

        st.subheader("📦 Bản mã nhận được")

        st.code(
            st.session_state.sent_ciphertext,
            language="text"
        )

    else:
        st.info(
            "Chưa có thông điệp từ A. "
            "Bạn vẫn có thể dán bản mã thủ công."
        )

    with st.form("decrypt_form"):

        st.subheader("🔐 Nhập Private Key")

        d_input = st.text_input(
            "Nhập d",
            placeholder="Ví dụ: 3343",
            type="password"
        )

        n_input = st.text_input(
            "Nhập n",
            placeholder="Ví dụ: 4819"
        )

        st.subheader("📨 Nhập bản mã")

        ciphertext_input = st.text_area(
            "Bản mã cần giải mã",
            value=st.session_state.sent_ciphertext,
            height=150
        )

        decrypt_button = st.form_submit_button(
            "🔓 Giải mã thông điệp",
            use_container_width=True
        )

    if decrypt_button:

        if not d_input.strip() or not n_input.strip():
            st.error("Vui lòng nhập đầy đủ Private Key.")

        elif not ciphertext_input.strip():
            st.error("Vui lòng nhập bản mã.")

        else:
            try:
                d = int(d_input)
                n = int(n_input)

                private_key = (d, n)

                ciphertext = parse_ciphertext(
                    ciphertext_input
                )

                plaintext = decrypt(
                    ciphertext,
                    private_key
                )

                st.success("Giải mã thành công!")

                st.subheader("📖 Thông điệp gốc")

                st.text_area(
                    "Nội dung sau giải mã",
                    value=plaintext,
                    height=150,
                    disabled=True
                )

            except ValueError as error:
                st.error(str(error))


# ==========================================
# FOOTER
# ==========================================
st.divider()

st.caption(
    "RSA SecureShare | Python + Streamlit | "
    "Educational RSA Demo"
)
