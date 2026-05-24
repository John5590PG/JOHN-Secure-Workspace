"""
======================================================================
JOHN SECURE WORKSPACE (V6.5 - ENTERPRISE INTERFACE)
Modul         : Front-End Workspace Environment (Streamlit)
Klasifikasi   : Terklasifikasi / Dokumen Internal
Deskripsi     : Antarmuka pengguna grafis (GUI) berbasis web.
                Menangani interaksi pengguna, rendering dinamis berdasarkan
                tingkat otorisasi (RBAC), dan persistensi data sementara
                menggunakan arsitektur Session State Streamlit.
======================================================================
"""

import streamlit as st
import mesin_web
import hashlib
import time
import secrets

# --- CONFIGURATION INTERFACES ---
# Mengatur tata letak halaman web menjadi "wide" untuk mengakomodasi 
# tabel log audit dan editor teks yang lebar secara optimal.
st.set_page_config(page_title="JOHN Secure Workspace v6.5", layout="wide")

# ==========================================
# FUNGSI BANTUAN (HELPER FUNCTIONS)
# ==========================================

def hash_password_login(password):
    """
    Mengubah kata sandi teks murni (plaintext) menjadi hash kriptografis.
    Mencegah pengiriman dan pemrosesan kata sandi asli secara telanjang
    di dalam alur otentikasi.
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def get_dummy_device_info():
    """
    Menyediakan data telemetri statis untuk prototipe.
    Dalam produksi skala penuh, fungsi ini harus dihubungkan dengan 
    middleware server (seperti reverse proxy NGINX) untuk menarik
    Alamat IP publik dan User-Agent perangkat keras yang sebenarnya.
    """
    return "192.168.1.100", "Enterprise Web Client Engine"

# ==========================================
# STATE MANAGEMENT LAYERS (PERSISTENSI SESI)
# ==========================================
# Karakteristik Streamlit akan memuat ulang (rerun) seluruh skrip dari baris 1
# setiap kali tombol ditekan. Session State (`st.session_state`) bertindak sebagai
# "Ingatan Jangka Pendek" agar server tidak melupakan status pengguna.

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'role' not in st.session_state:
    st.session_state.role = ""

# STATE PERSISTENSI EDITOR
# Digunakan khusus untuk menahan teks hasil dekripsi agar tidak hilang
# dari layar saat pengguna sedang mengetik perubahan.
if 'edit_lokal_teks' not in st.session_state:
    st.session_state.edit_lokal_teks = None
if 'edit_cloud_id' not in st.session_state:
    st.session_state.edit_cloud_id = None
if 'edit_cloud_teks' not in st.session_state:
    st.session_state.edit_cloud_teks = None

# Memastikan tabel pangkalan data siap sebelum antarmuka dirender
mesin_web.inisialisasi_database()

# ==========================================
# CONTROL GATEWAY: AUTENTIKASI AKSES
# ==========================================
def halaman_autentikasi():
    """
    Merender antarmuka pintu masuk sistem.
    Terbagi menjadi dua kolom: Login Kredensial dan Registrasi Entitas.
    Menangani alur pembuatan API Key otomatis untuk entitas 'Service'.
    """
    st.title("Sistem Manajemen Akses Terintegrasi .JOHN")
    st.markdown("Dokumen internal dan infrastruktur kriptografi terklasifikasi. Otorisasi diperlukan.")
    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Pintu Otorisasi Kredensial")
        login_user = st.text_input("Identitas Pengguna (Username)", key="login_user")
        login_pass = st.text_input("Kata Sandi Akun", type="password", key="login_pass")
        
        if st.button("Autentikasi Sesi"):
            ip_dummy, device_dummy = get_dummy_device_info()
            pass_hash = hash_password_login(login_pass)
            
            hasil = mesin_web.verifikasi_login(login_user, pass_hash, ip_dummy, device_dummy)
            
            if hasil["status"] == "SUKSES":
                # Validasi Autentikasi Adaptif
                if hasil["peringatan_ip"]:
                    st.warning("Pemberitahuan Sistem: Deteksi anomali sesi jaringan. Sesi dicatat.")
                
                # Mengisi parameter sesi agar gerbang dashboard terbuka
                st.session_state.logged_in = True
                st.session_state.username = login_user
                st.session_state.user_id = hasil["id"]
                st.session_state.role = hasil["role"]
                
                mesin_web.catat_audit_log(hasil["id"], login_user, "ACCESS_AUTHORIZED", "None", ip_dummy, device_dummy)
                st.success("Otorisasi diterima. Menginisialisasi lingkungan kerja...")
                time.sleep(1)
                st.rerun() # Memaksa muat ulang agar skrip masuk ke blok halaman_dashboard_user()
                
            elif hasil["status"] == "RESTRICTED_PENDING_DELETION":
                st.error("Akses Dibatasi: Akun Anda sedang berada dalam siklus peninjauan deaktivasi permanen.")
            else:
                mesin_web.catat_audit_log(None, login_user, "UNAUTHORIZED_ATTEMPT", "None", ip_dummy, device_dummy)
                st.error("Kegagalan otentikasi. Kredensial tidak valid.")

    with col2:
        st.subheader("Registrasi Entitas Baru")
        reg_user = st.text_input("Nama Entitas Baru", key="reg_user")
        reg_pass = st.text_input("Kata Sandi Entitas", type="password", key="reg_pass")
        
        # SISTEM ENTERPRISE: Kolom rahasia untuk afiliasi B2B atau Admin
        st.markdown("---")
        st.caption("Khusus Afiliasi B2B / Karyawan Internal:")
        reg_kode = st.text_input("Kode Otorisasi Khusus (Opsional)", type="password", key="reg_kode", help="Kosongkan jika Anda adalah entitas pengguna reguler.")
        
        # DEFINISI KODE RAHASIA SERVER (DI DUNIA NYATA, INI DISIMPAN DI FILE .ENV)
        KODE_RAHASIA_ADMIN = "JOHN-OMEGA-ADMIN-99X"
        KODE_RAHASIA_PABRIK = "JOHN-NEXUS-B2B-77Y"
        
        if st.button("Daftarkan Entitas"):
            if reg_user and reg_pass:
                pass_hash = hash_password_login(reg_pass)
                
                # EVALUASI KASTA BERDASARKAN KODE OTORISASI (BUKAN NAMA)
                if reg_kode == KODE_RAHASIA_ADMIN:
                    role_otomatis = "Admin"
                elif reg_kode == KODE_RAHASIA_PABRIK:
                    role_otomatis = "Service"
                else:
                    role_otomatis = "User" # Default mutlak jika kosong atau kode salah
                
                # Pembangkitan Token API kriptografis murni (M2M) jika role adalah Service
                api_key_generated = f"JOHN-API-{secrets.token_hex(16)}" if role_otomatis == "Service" else None
                
                sukses = mesin_web.tambah_user(reg_user, pass_hash, role=role_otomatis, api_key=api_key_generated)
                if sukses:
                    st.success(f"Entitas berhasil terdaftar. Klasifikasi Otorisasi: {role_otomatis}.")
                    
                    # Berikan notifikasi khusus jika mereka menggunakan kode afiliasi yang benar
                    if role_otomatis == "Admin":
                        st.info("Otorisasi Eksekutif dikenali. Selamat bekerja, Admin.")
                    elif role_otomatis == "Service":
                        st.info(f"Kunci Token Akses API (M2M) Anda: `{api_key_generated}`. Salin segera untuk konfigurasi program afiliasi.")
                else:
                    st.error("Gagal mendaftarkan entitas. Identitas sudah terikat dengan sistem lain.")
            else:
                st.warning("Formulir pendaftaran (Nama dan Sandi) tidak boleh kosong.")

# ==========================================
# CORE WORKSPACE ENVIRONMENT (DASHBOARD)
# ==========================================
def halaman_dashboard_user():
    """
    Merender infrastruktur utama setelah pengguna terotorisasi.
    Menggunakan panel navigasi samping (Sidebar) yang dinamis
    tergantung pada tingkat otorisasi (RBAC).
    """
    st.sidebar.title("JOHN Workspace Control")
    st.sidebar.markdown(f"**Identitas:** {st.session_state.username}")
    st.sidebar.markdown(f"**Klasifikasi Otorisasi:** {st.session_state.role}")
    st.sidebar.markdown("---")

    menu_opsi = ["Enkripsi Berkas Baru", "Dekripsi Berkas Lokal", "Penyimpanan Cloud", "Pengaturan Akun"]
    
    # Hak akses berjenjang: Membuka menu Audit Trail untuk kelas Administrator
    if st.session_state.role in ["Admin", "Super_Admin"]:
        menu_opsi.append("Log Audit Infrastruktur")

    menu = st.sidebar.radio("Navigasi Infrastruktur", menu_opsi)
    st.sidebar.markdown("---")
    
    # Protokol Terminasi Sesi (Pembersihan Ingatan Server)
    if st.sidebar.button("Terminasi Sesi (Logout)"):
        ip_dummy, device_dummy = get_dummy_device_info()
        mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "SESSION_TERMINATED", "None", ip_dummy, device_dummy)
        st.session_state.clear()
        st.rerun()

    # ----------------------------------------
    # MENU A: ENKRIPSI BARU
    # ----------------------------------------
    if menu == "Enkripsi Berkas Baru":
        st.header("Enkripsi & Enkapsulasi Berkas")
        pesan_rahasia = st.text_area("Input Struktur Data Tekstual / Konfigurasi Timeline:", height=150)
        sandi_brankas = st.text_input("Kunci Kriptografi (Sandi Enkripsi Berkas):", type="password")
        
        mode_penyimpanan = st.selectbox("Arsitektur Distribusi Target:", ["Ekstraksi Lokal (Unduh Berkas)", "Infrastruktur Cloud Penyimpanan Server"])
        nama_file = st.text_input("Identitas Fisik Berkas (Tanpa Ekstensi):", "Timeline_Matrix_Config")
        
        # Validasi Input: Mesin hanya akan merakit jika data tidak kosong
        if pesan_rahasia and sandi_brankas:
            # Merakit biner secara volatil di memori RAM server
            data_biner = mesin_web.buat_file_john_web(pesan_rahasia, sandi_brankas)
            nama_file_lengkap = f"{nama_file}.John"
            ip_dummy, device_dummy = get_dummy_device_info()

            if mode_penyimpanan == "Ekstraksi Lokal (Unduh Berkas)":
                st.info("Status: Siap diunduh. Data tidak akan disimpan di server.")
                # st.download_button tidak boleh dibungkus dalam st.button untuk mencegah isu Refresh Ghosting
                if st.download_button(label="📥 Eksekusi & Unduh Berkas Ekstensi .John", data=data_biner, file_name=nama_file_lengkap, mime="application/octet-stream"):
                    mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "ENCRYPT_LOCAL_SUCCESS", nama_file_lengkap, ip_dummy, device_dummy)
                    st.success("Operasi berhasil. Berkas telah diekstraksi ke penyimpanan perangkat Anda.")
            
            elif mode_penyimpanan == "Infrastruktur Cloud Penyimpanan Server":
                if st.button("☁️ Eksekusi Kompilasi & Simpan ke Cloud"):
                    mesin_web.simpan_brankas_cloud(st.session_state.user_id, nama_file_lengkap, data_biner)
                    mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "ENCRYPT_CLOUD_SUCCESS", nama_file_lengkap, ip_dummy, device_dummy)
                    st.success(f"Objek biner '{nama_file_lengkap}' berhasil disuntikkan ke dalam basis data Cloud server.")
        else:
            st.warning("Parameter data tekstual dan Kunci Kriptografi wajib diisi untuk mengaktifkan fungsi kompilasi.")

    # ----------------------------------------
    # MENU B: DEKRIPSI & EDIT LOKAL
    # ----------------------------------------
    elif menu == "Dekripsi Berkas Lokal":
        st.header("Dekripsi & Modifikasi Konten Lokal")
        st.markdown("Proses manipulasi objek dilakukan secara volatil pada memori RAM server tanpa retensi data.")
        
        file_unggahan = st.file_uploader("Pilih Berkas .John Lokal", type=None)
        
        # Membersihkan ingatan State jika pengguna membatalkan/menghapus file unggahan
        if file_unggahan is None:
            st.session_state.edit_lokal_teks = None
            
        if file_unggahan is not None:
            sandi_buka = st.text_input("Kunci Dekripsi Berkas:", type="password")
            
            if st.button("Eksekusi Dekripsi Objek"):
                data_biner = file_unggahan.read()
                hasil_dekripsi = mesin_web.ekstrak_file_john_web(data_biner, sandi_buka)
                ip_dummy, device_dummy = get_dummy_device_info()
                
                if hasil_dekripsi.startswith("ERROR"):
                    mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "DECRYPT_LOCAL_FAILED", file_unggahan.name, ip_dummy, device_dummy)
                    st.error("Gagal mendekripsi: Kunci kriptografi tidak valid atau header file terkorupsi.")
                    st.session_state.edit_lokal_teks = None
                else:
                    mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "DECRYPT_LOCAL_SUCCESS", file_unggahan.name, ip_dummy, device_dummy)
                    st.success("Otorisasi berkas sukses. Konten terekstraksi ke dalam editor.")
                    st.session_state.edit_lokal_teks = hasil_dekripsi # Menyimpan hasil ke persistensi sesi

            # Merender editor Teks hanya jika terdapat data di persistensi sesi
            if st.session_state.edit_lokal_teks is not None:
                st.markdown("---")
                st.subheader("Data Editor Layer")
                teks_baru = st.text_area("Konten Dokumen Modifikasi:", value=st.session_state.edit_lokal_teks, height=200)
                sandi_baru = st.text_input("Kunci Kriptografi Baru (Untuk Kompilasi Ulang):", type="password")
                
                if sandi_baru and teks_baru:
                    data_biner_baru = mesin_web.buat_file_john_web(teks_baru, sandi_baru)
                    st.download_button(label="Kunci Ulang & Unduh Pembaruan", data=data_biner_baru, file_name=file_unggahan.name, mime="application/octet-stream")

    # ----------------------------------------
    # MENU C: GUDANG CLOUD & EDIT
    # ----------------------------------------
    elif menu == "Penyimpanan Cloud":
        st.header("Manajemen Infrastruktur Data Cloud")
        
        daftar_file = mesin_web.ambil_daftar_brankas_cloud(st.session_state.user_id)
        
        if not daftar_file:
            st.info("Tidak ada aset objek terenkripsi yang terdaftar di akun Anda.")
        else:
            pilihan_file = st.selectbox("Pilih berkas repositori:", [f"{f[0]} - {f[1]}" for f in daftar_file])
            
            if pilihan_file:
                file_id = int(pilihan_file.split(" - ")[0])
                nama_file = pilihan_file.split(" - ")[1]
                
                sandi_buka_cloud = st.text_input("Kunci Dekripsi Berkas Cloud:", type="password")
                
                if st.button("Eksekusi Penarikan & Dekripsi Cloud"):
                    data_mentah = mesin_web.ambil_data_brankas_cloud(file_id, st.session_state.user_id)
                    if data_mentah:
                        hasil_dekripsi = mesin_web.ekstrak_file_john_web(data_mentah[0], sandi_buka_cloud)
                        ip_dummy, device_dummy = get_dummy_device_info()
                        
                        if hasil_dekripsi.startswith("ERROR"):
                            mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "DECRYPT_CLOUD_FAILED", nama_file, ip_dummy, device_dummy)
                            st.error("Kunci kriptografi objek cloud salah.")
                            st.session_state.edit_cloud_id = None
                        else:
                            mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "DECRYPT_CLOUD_SUCCESS", nama_file, ip_dummy, device_dummy)
                            st.success("Dekripsi cloud berhasil. Editor internal aktif.")
                            # Menyimpan ID & Teks ke persistensi sesi agar dapat ditimpa (Update) nantinya
                            st.session_state.edit_cloud_id = file_id
                            st.session_state.edit_cloud_teks = hasil_dekripsi

                # Logika Edit-In-Place Cloud (Hanya aktif jika ID file cocok dengan memori sesi)
                if st.session_state.edit_cloud_id == file_id:
                    st.markdown("---")
                    st.subheader(f"Cloud Editor Mode: {nama_file}")
                    teks_cloud_baru = st.text_area("Isi Konfigurasi Dokumen:", value=st.session_state.edit_cloud_teks, height=200)
                    sandi_cloud_baru = st.text_input("Kunci Kriptografi Pembaruan (Wajib):", type="password", key="sandi_cloud_baru")
                    
                    if st.button("Terapkan Enkripsi & Timpa Aset Server"):
                        if teks_cloud_baru and sandi_cloud_baru:
                            biner_cloud_baru = mesin_web.buat_file_john_web(teks_cloud_baru, sandi_cloud_baru)
                            mesin_web.perbarui_brankas_cloud(file_id, st.session_state.user_id, biner_cloud_baru)
                            
                            ip_dummy, device_dummy = get_dummy_device_info()
                            mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "UPDATE_CLOUD_SUCCESS", nama_file, ip_dummy, device_dummy)
                            
                            st.success("Sinkronisasi aset cloud server berhasil diperbarui.")
                            st.session_state.edit_cloud_id = None
                            time.sleep(1)
                            st.rerun() # Refresh untuk memuat ulang daftar file terbaru

    # ----------------------------------------
    # MENU D: WORKFLOW PENGATURAN AKUN & HAPUS
    # ----------------------------------------
    elif menu == "Pengaturan Akun":
        st.header("Manajemen Kredensial & Kebijakan Akun")
        
        tab_p1, tab_p2 = st.tabs(["Ubah Kata Sandi Sesi", "Protokol Pemusnahan Akun"])
        
        # Fungsionalitas Update Kredensial (Membutuhkan verifikasi sandi lama)
        with tab_p1:
            sandi_lama = st.text_input("Kata Sandi Saat Ini", type="password")
            sandi_baru = st.text_input("Kata Sandi Akun Baru", type="password")
            sandi_konfirmasi = st.text_input("Konfirmasi Kata Sandi Akun Baru", type="password")
            
            if st.button("Perbarui Kredensial Otentikasi"):
                if sandi_baru != sandi_konfirmasi:
                    st.error("Kesalahan validasi: Konfirmasi kata sandi baru tidak identik.")
                else:
                    hash_lama = hash_password_login(sandi_lama)
                    hash_baru = hash_password_login(sandi_baru)
                    sukses = mesin_web.ubah_sandi_akun(st.session_state.user_id, hash_lama, hash_baru)
                    ip_dummy, device_dummy = get_dummy_device_info()
                    
                    if sukses:
                        mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "CREDENTIAL_UPDATE_SUCCESS", "Account", ip_dummy, device_dummy)
                        st.success("Pembaruan hash kredensial berhasil disimpan.")
                    else:
                        mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "CREDENTIAL_UPDATE_FAILED", "Account", ip_dummy, device_dummy)
                        st.error("Gagal melakukan pembaruan. Kata sandi saat ini tidak valid.")

        # Protokol Retensi Data dan Deaktivasi (Proses Destruktif Berisiko Tinggi)
        with tab_p2:
            st.error("🚨 ZONA PROTEKSI RETENSI DATA")
            st.markdown("Tindakan di bawah ini bersifat destruktif. Seluruh aset cloud yang terikat dengan ID entitas Anda akan dihapus secara permanen dari basis data.")
            
            # Peringatan Retensi Dinamis (Hitung aset yang akan musnah)
            jumlah_berkas = mesin_web.hitung_berkas_pengguna(st.session_state.user_id)
            if jumlah_berkas > 0:
                st.warning(f"Peringatan Retensi: Deteksi mendeteksi terdapat {jumlah_berkas} berkas terenkripsi milik Anda di server Cloud yang akan ikut dimusnahkan.")
                
            password_konfirmasi_hapus = st.text_input("Masukkan Kata Sandi Akun Anda Sebagai Otorisasi Akhir:", type="password")
            
            # ATURAN DIFERENSIASI PENGHAPUSAN AKUN (USER VS ADMIN)
            if st.session_state.role in ["Admin", "Super_Admin"]:
                st.info("Kebijakan Tata Kelola: Akun dengan tingkat otorisasi Admin memerlukan persetujuan manual Super_Admin sebelum proses destruksi data dieksekusi.")
                if st.button("Ajukan Deaktivasi Akun Administrasi"):
                    if password_konfirmasi_hapus:
                        pass_hash = hash_password_login(password_konfirmasi_hapus)
                        sukses = mesin_web.ajukan_penghapusan_admin(st.session_state.user_id, pass_hash)
                        if sukses:
                            ip_dummy, device_dummy = get_dummy_device_info()
                            mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, "DELETION_REQUEST_SUBMITTED", "Account", ip_dummy, device_dummy)
                            st.success("Permintaan pengunduran diri dan penghapusan akun berhasil dikirim ke antrean Super_Admin. Sesi Anda ditangguhkan.")
                            time.sleep(2)
                            st.session_state.clear()
                            st.rerun()
                        else:
                            st.error("Verifikasi otorisasi gagal. Kata sandi salah.")
            else:
                # Alur pengguna biasa: Hapus langsung secara Cascade
                if st.button("Eksekusi Pemusnahan Akun Mandiri"):
                    if password_konfirmasi_hapus:
                        pass_hash = hash_password_login(password_konfirmasi_hapus)
                        sukses = mesin_web.eksekusi_penghapusan_pengguna_umum(st.session_state.user_id, pass_hash)
                        if sukses:
                            st.success("Siklus pemusnahan selesai. Seluruh data biner Anda telah dibumihanguskan dari server.")
                            time.sleep(2)
                            st.session_state.clear()
                            st.rerun()
                        else:
                            st.error("Verifikasi otorisasi gagal. Kata sandi salah.")

    # ----------------------------------------
    # MENU E: MONITOR AUDIT INFRASTRUKTUR (ADMIN/SUPER)
    # ----------------------------------------
    elif menu == "Log Audit Infrastruktur":
        st.header("Sistem Audit Transparansi Absolut (Audit Trail)")
        
        import sqlite3
        import pandas as pd
        
        try:
            conn = sqlite3.connect(mesin_web.DB_PATH)
            # Menarik log audit ke dalam kerangka kerja Pandas untuk tampilan tabular interaktif
            st.subheader("Perekaman Jejak Aktivitas Sesi (Top 100 Entries)")
            df_logs = pd.read_sql_query("SELECT timestamp, username, action, target_file, ip_address, device_info FROM audit_logs ORDER BY timestamp DESC LIMIT 100", conn)
            st.dataframe(df_logs, use_container_width=True)
            
            st.subheader("Buku Induk Registrasi Entitas Server")
            df_users = pd.read_sql_query("SELECT id, username, role, account_status, last_ip, created_at FROM users", conn)
            st.dataframe(df_users, use_container_width=True)
            conn.close()
        except Exception:
            st.error("Gagal menjalin interkoneksi ke basis data audit terklasifikasi.")
            
        # ==========================================
        # PANEL HIERARKI UTAMA: KHUSUS SUPER_ADMIN (JOHN_ADMIN)
        # ==========================================
        if st.session_state.role == "Super_Admin":
            st.markdown("---")
            st.subheader("👑 PANEL OTORISASI MAHKOTA (SUPER_ADMIN CONTROL)")
            st.markdown("Manajemen peninjauan permohonan deaktifasi akun tingkat Admin.")
            
            daftar_tertunda = mesin_web.ambil_daftar_penghapusan_tertunda()
            
            if not daftar_tertunda:
                st.info("Antrean kliring keamanan kosong. Tidak ada permohonan deaktifasi Admin tertunda.")
            else:
                for target in daftar_tertunda:
                    t_id, t_user, t_time = target
                    col_sa1, col_sa2, col_sa3 = st.columns([2, 1, 1])
                    
                    with col_sa1:
                        st.warning(f"Permohonan Destruksi Akun: Admin '{t_user}' (Terdaftar Sejak: {t_time})")
                    with col_sa2:
                        if st.button("SETUJUI DESTRUKSI PERMANEN", key=f"setuju_{t_id}"):
                            mesin_web.proses_keputusan_deaktivasi_admin(t_id, "SETUJU")
                            ip_dummy, device_dummy = get_dummy_device_info()
                            mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, f"SUPER_ADMIN_APPROVED_DELETION_OF_{t_user}", "Account", ip_dummy, device_dummy)
                            st.success(f"Akun Admin '{t_user}' dan seluruh datanya telah dimusnahkan secara absolut.")
                            time.sleep(1)
                            st.rerun()
                    with col_sa3:
                        if st.button("TOLAK PERMOHONAN & RE-AKTIVASI", key=f"tolak_{t_id}"):
                            mesin_web.proses_keputusan_deaktivasi_admin(t_id, "TOLAK")
                            ip_dummy, device_dummy = get_dummy_device_info()
                            mesin_web.catat_audit_log(st.session_state.user_id, st.session_state.username, f"SUPER_ADMIN_REJECTED_DELETION_OF_{t_user}", "Account", ip_dummy, device_dummy)
                            st.info(f"Permohonan ditolak. Hak akses '{t_user}' dipulihkan ke status aktif.")
                            time.sleep(1)
                            st.rerun()

# ==========================================
# GATEWAY ROUTER (PENERUS ALUR APLIKASI)
# ==========================================
# Memutuskan halaman mana yang akan dirender berdasarkan status memori sesi
if not st.session_state.logged_in:
    halaman_autentikasi()
else:
    halaman_dashboard_user()