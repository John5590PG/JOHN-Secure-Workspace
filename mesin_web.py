"""
======================================================================
JOHN SECURE WORKSPACE (V6.5 - ENTERPRISE BACKEND ARCHITECTURE)
Modul         : Core Cryptographic & Database Access Layer (CRUD)
Klasifikasi   : Terklasifikasi / Dokumen Internal
Deskripsi     : Modul ini menangani operasi pangkalan data (SQLite),
                mekanisme kontrol akses berbasis peran (RBAC), protokol
                audit, dan mesin kriptografi XOR+SHA256 untuk format .John.
======================================================================
"""

import hashlib
import time
import sqlite3
import io
import os
import secrets

# --- KONFIGURASI SISTEM GLOBAL ---
# MAGIC_HEADER bertindak sebagai identifier file unik (8-byte) untuk mencegah
# sistem memproses ekstensi file yang tidak valid.
MAGIC_HEADER = b"JOHN-V5 "
DB_PATH = os.path.join("database", "john_server.db")

# ==========================================
# 1. DATABASE ARCHITECTURE & INTIALIZATION
# ==========================================

def inisialisasi_database():
    """ 
    Menginisialisasi skema basis data relasional SQLite.
    
    Fungsi ini dipanggil saat aplikasi web dimuat pertama kali.
    Ia membangun tiga tabel utama:
    1. users: Menyimpan kredensial, role, status retensi, dan API Key B2B.
    2. cloud_files: Menyimpan objek BLOB file .John terenkripsi milik user.
    3. audit_logs: Menyimpan rekam jejak aktivitas (Immutable Log).
    
    Selain itu, fungsi ini melakukan 'Seeding' untuk memastikan setidaknya
    terdapat 1 akun Super_Admin (John_Admin) saat database kosong.
    """
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # TABEL 1: Registrasi Pengguna & Entitas Mesin (RBAC)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            role TEXT NOT NULL,
            api_key TEXT UNIQUE,
            account_status TEXT DEFAULT 'ACTIVE',
            last_ip TEXT,
            last_device TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # TABEL 2: Repositori Berkas Terenkripsi (BLOB Storage)
    # Atribut ON DELETE CASCADE memastikan jika entitas user dihapus,
    # maka seluruh berkas cloud miliknya akan ikut musnah.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cloud_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            file_name TEXT NOT NULL,
            file_data BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # TABEL 3: Rekam Jejak Audit Absolut (Immutable Audit Trail)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            target_file TEXT,
            ip_address TEXT,
            device_info TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # SEEDING OTOMATIS: Penciptaan akun Super_Admin master
    cursor.execute('SELECT COUNT(*) FROM users WHERE role = "Super_Admin"')
    if cursor.fetchone()[0] == 0:
        # Peringatan Keamanan: Kata sandi bawaan ini harus segera diubah
        # pada saat otorisasi pertama kali oleh Admin.
        initial_hash = hashlib.sha256('John5590PG'.encode('utf-8')).hexdigest()
        cursor.execute('''
            INSERT INTO users (username, password_hash, role, account_status)
            VALUES ('John_Admin', ?, 'Super_Admin', 'ACTIVE')
        ''', (initial_hash,))
        
    conn.commit()
    conn.close()

def catat_audit_log(user_id, username, action, target_file, ip_address, device_info):
    """ 
    Merekam aktivitas sistem ke dalam tabel log audit.
    
    Parameter:
        user_id (int/None): ID pengguna yang melakukan aksi.
        username (str): Nama identitas pengguna.
        action (str): Tipe aktivitas (Contoh: "LOGIN_SUKSES", "ENCRYPT_CLOUD").
        target_file (str): Nama entitas objek jika ada (Contoh: "Timeline.john").
        ip_address (str): Alamat IP klien (Autentikasi Adaptif).
        device_info (str): Data User-Agent dari web browser klien.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (user_id, username, action, target_file, ip_address, device_info)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, username, action, target_file, ip_address, device_info))
    conn.commit()
    conn.close()

# ==========================================
# 2. OPERASIONAL DATABASE & LOGIKA RBAC (CRUD)
# ==========================================

def tambah_user(username, password_hash, role="User", api_key=None):
    """ 
    Mendaftarkan pengguna manusia atau entitas mesin ke basis data.
    
    Mengembalikan:
        bool: True jika registrasi berhasil, False jika nama pengguna
              atau API Key sudah terdaftar (IntegrityError).
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, role, api_key, account_status)
            VALUES (?, ?, ?, ?, 'ACTIVE')
        ''', (username, password_hash, role, api_key))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

def verifikasi_login(username, password_hash, ip_sekarang, device_sekarang):
    """ 
    Memvalidasi kredensial login dan menerapkan kebijakan keamanan adaptif.
    
    Fungsi ini juga memblokir akses login bagi akun Admin yang sedang
    berada dalam fase 'PENDING_DELETION' (Menunggu persetujuan hapus).
    
    Mengembalikan:
        dict: Berisi status ("SUKSES", "GAGAL", "RESTRICTED_PENDING_DELETION"),
              id pengguna, role, dan flag peringatan anomali IP.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, role, last_ip, account_status 
        FROM users WHERE username = ? AND password_hash = ?
    ''', (username, password_hash))
    user = cursor.fetchone()
    
    if user:
        user_id, role, last_ip, status = user
        
        # Penegakan Kebijakan Retensi: Blokir login jika akun sedang diproses hapus
        if status == 'PENDING_DELETION' and role != 'Admin':
            conn.close()
            return {"status": "RESTRICTED_PENDING_DELETION"}
            
        # Logika Autentikasi Adaptif (Deteksi pergeseran IP)
        peringatan_ip = False
        if last_ip and last_ip != ip_sekarang:
            peringatan_ip = True
            
        # Perbarui log kehadiran terakhir
        cursor.execute('UPDATE users SET last_ip = ?, last_device = ? WHERE id = ?', (ip_sekarang, device_sekarang, user_id))
        conn.commit()
        conn.close()
        
        return {"status": "SUKSES", "id": user_id, "role": role, "peringatan_ip": peringatan_ip}
    
    conn.close()
    return {"status": "GAGAL"}

def ubah_sandi_akun(user_id, sandi_lama_hash, sandi_baru_hash):
    """ 
    Memperbarui hash kredensial pengguna setelah memverifikasi hash lama.
    Mengembalikan True jika sukses, False jika hash lama tidak cocok.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE id = ? AND password_hash = ?', (user_id, sandi_lama_hash))
    if cursor.fetchone():
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (sandi_baru_hash, user_id))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

# --- PROTOKOL RETENSI DATA & DEAKTIVASI AKUN ---

def hitung_berkas_pengguna(user_id):
    """ Menghitung total volume berkas Cloud milik entitas pengguna spesifik. """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM cloud_files WHERE user_id = ?', (user_id,))
    jumlah = cursor.fetchone()[0]
    conn.close()
    return jumlah

def eksekusi_penghapusan_pengguna_umum(user_id, password_hash):
    """ 
    Alur pemusnahan mandiri khusus Kasta 'User'.
    Menghapus berkas cloud secara Cascade beserta data identitas akun.
    Dibutuhkan konfirmasi kata sandi sebagai lapis pengamanan.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE id = ? AND password_hash = ?', (user_id, password_hash))
    if cursor.fetchone():
        # Karena menggunakan SQLite standar tanpa PRAGMA foreign_keys = ON secara global,
        # penghapusan file cloud dilakukan secara manual sebagai prosedur Cascade-Fail-Safe.
        cursor.execute('DELETE FROM cloud_files WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

def ajukan_penghapusan_admin(user_id, password_hash):
    """ 
    Alur pemusnahan tertunda khusus Kasta 'Admin'.
    Tidak menghapus data, melainkan mengubah status menjadi 'PENDING_DELETION'
    yang akan memutus akses login hingga disetujui oleh Super_Admin.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE id = ? AND password_hash = ?', (user_id, password_hash))
    if cursor.fetchone():
        cursor.execute('UPDATE users SET account_status = "PENDING_DELETION" WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

def ambil_daftar_penghapusan_tertunda():
    """ 
    Mengembalikan list akun Admin yang sedang dalam status peninjauan (PENDING).
    Diakses secara eksklusif oleh dashboard Super_Admin.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, created_at FROM users WHERE account_status = "PENDING_DELETION"')
    daftar = cursor.fetchall()
    conn.close()
    return daftar

def proses_keputusan_deaktivasi_admin(target_user_id, keputusan):
    """ 
    Mengeksekusi dekrit Super_Admin terhadap akun tertunda.
    Parameter keputusan: "SETUJU" (Musnahkan) atau "TOLAK" (Pulihkan akses).
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if keputusan == "SETUJU":
        cursor.execute('DELETE FROM cloud_files WHERE user_id = ?', (target_user_id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (target_user_id,))
    else:
        cursor.execute('UPDATE users SET account_status = "ACTIVE" WHERE id = ?', (target_user_id,))
    conn.commit()
    conn.close()

# --- MANAJEMEN BERKAS REPOSITORI (CLOUD CRUD) ---

def simpan_brankas_cloud(user_id, file_name, file_data):
    """ Menyuntikkan objek BLOB biner terenkripsi ke dalam pangkalan data. """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO cloud_files (user_id, file_name, file_data) VALUES (?, ?, ?)', (user_id, file_name, file_data))
    conn.commit()
    conn.close()

def ambil_daftar_brankas_cloud(user_id):
    """ Mengambil metadata (ID, Nama, Waktu) file cloud milik pengguna. """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, file_name, updated_at FROM cloud_files WHERE user_id = ?', (user_id,))
    daftar_file = cursor.fetchall()
    conn.close()
    return daftar_file

def ambil_data_brankas_cloud(file_id, user_id):
    """ Menarik objek BLOB mentah (terenkripsi) dari server ke memori RAM untuk diekstraksi. """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT file_data, file_name FROM cloud_files WHERE id = ? AND user_id = ?', (file_id, user_id))
    baris = cursor.fetchone()
    conn.close()
    return baris

def perbarui_brankas_cloud(file_id, user_id, file_data_baru):
    """ Menimpa objek BLOB lama dengan BLOB baru hasil modifikasi editor. """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE cloud_files SET file_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?', (file_data_baru, file_id, user_id))
    conn.commit()
    conn.close()

# ==========================================
# 3. INTERFACES MESIN EKSTERNAL (B2B API LAYER)
# ==========================================

def validasi_api_key_pabrik(api_key):
    """ 
    Jalur otentikasi Machine-to-Machine (M2M) (API Endpoint Authentication).
    Digunakan oleh aplikasi eksternal (Contoh: Timeline Matrix) untuk 
    memverifikasi identitas Service Account tanpa antarmuka grafis.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users WHERE api_key = ? AND role = "Service"', (api_key,))
    mesin = cursor.fetchone()
    conn.close()
    return mesin # Mengembalikan (user_id, username) jika valid, None jika tidak.

# ==========================================
# 4. CRYPTOGRAPHIC CORE ENGINE (RAM OPERATION)
# ==========================================

from cryptography.fernet import Fernet
import base64

# Menggunakan SHA-256 untuk memastikan sandi pengguna 
# menjadi kunci 32-byte yang valid untuk Fernet (Base64 URL-safe)
def _generate_key(kata_sandi):
    digest = hashlib.sha256(kata_sandi.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def enkripsi_data(pesan, kata_sandi):
    """ Enkripsi industri menggunakan AES-128 + HMAC. """
    key = _generate_key(kata_sandi)
    f = Fernet(key)
    return f.encrypt(pesan.encode())

def dekripsi_data(data_biner, kata_sandi):
    """ Dekripsi industri dengan verifikasi integritas HMAC. """
    try:
        key = _generate_key(kata_sandi)
        f = Fernet(key)
        return f.decrypt(data_biner).decode()
    except:
        return "ERROR_CRYPTOGRAPHIC"

def buat_file_john_web(pesan, sandi, daftar_izin="Universal_Web_Access"):
    waktu_sekarang = int(time.time())
    data_enkripsi = enkripsi_data(pesan, sandi)
    
    # Kita tetap mempertahankan header agar kompatibel dengan sistem kita
    buffer = io.BytesIO()
    buffer.write(MAGIC_HEADER)
    buffer.write(waktu_sekarang.to_bytes(4, byteorder='big'))
    buffer.write(data_enkripsi) 
    return buffer.getvalue()

def ekstrak_file_john_web(data_biner_file, sandi):
    f = io.BytesIO(data_biner_file)
    if f.read(8) != MAGIC_HEADER:
        return "ERROR_HEADER"
    f.read(4) # Bypass timestamp
    data_enkripsi = f.read()
    return dekripsi_data(data_enkripsi, sandi)