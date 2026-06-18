#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Şifre Kasası - Offline parola yöneticisi (macOS)

Güvenlik mimarisi:
  - Master parola hiçbir yere kaydedilmez.
  - Master parola + rastgele salt  -> Argon2id (256 MB) -> 256-bit disk anahtarı.
  - Tüm kasa AES-256-GCM ile şifrelenir (gizlilik + bütünlük).
  - Diskte: MAGIC | VERSİYON | salt | nonce | şifreli veri.

  Bellek güvenliği:
  - Disk anahtarı SecureBuffer içinde mlock ile swap'a yazılmaz.
  - Vault açıldıktan sonra parolalar bellekte plaintext kalmaz;
    EncryptedStore içinde rastgele bir oturum anahtarıyla AES-GCM şifrelenir.
  - Hesap adı ve kullanıcı adı tablo gösterimi için plaintext tutulur;
    gerçek parolalar yalnızca kopyalama/düzenleme anında tek tek çözülür.
  - Disk yazımında plaintext bytearray kullanılır ve sıfırlanır.
  - Kilitlemede oturum anahtarı ve tüm veri bellekten silinir.
  - 5 dakika hareketsizlikte otomatik kilitleme.
  - Yanlış denemelerde üstel gecikme.

Kurulum:
  pip3 install argon2-cffi cryptography zxcvbn

Çalıştırma:
  python3 casa.py
"""

import os
import json
import time
import ctypes
import ctypes.util
import tkinter as tk
from tkinter import ttk, messagebox

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

try:
    from zxcvbn import zxcvbn as _zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

# ---------------------------------------------------------------------------
# Ayarlar
# ---------------------------------------------------------------------------
VAULT_FILE = os.path.join(os.path.expanduser("~"), ".sifre_kasasi.dat")
VAULT_MAGIC = b"CASA"
VAULT_VERSION = 1

# Argon2id — 256 MB bellek (GPU/ASIC saldırılarına karşı maksimum direnç)
ARGON_TIME = 4
ARGON_MEMORY = 256 * 1024   # KiB = 256 MB
ARGON_PARALLELISM = 4
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

CLIPBOARD_CLEAR_MS = 15_000    # pano 15 sn sonra temizlenir
LOCK_TIMEOUT_MS = 5 * 60_000   # 5 dk hareketsizlikte kilitle
MASK = "•" * 8


# ---------------------------------------------------------------------------
# Güvenli bellek tamponu (mlock + sıfırlama)
# ---------------------------------------------------------------------------
class SecureBuffer:
    """
    Hassas veriyi mlock ile swap-korumalı bellekte tutar.
    wipe() çağrıldığında içeriği sıfırlar ve kilidi açar.
    """

    _libc = None

    @classmethod
    def _get_libc(cls):
        if cls._libc is None:
            try:
                cls._libc = ctypes.CDLL(ctypes.util.find_library("c"))
            except Exception:
                pass
        return cls._libc

    def __init__(self, data: bytes):
        self._len = len(data)
        self._buf = ctypes.create_string_buffer(data, self._len)
        libc = self._get_libc()
        if libc:
            try:
                libc.mlock(self._buf, ctypes.c_size_t(self._len))
            except Exception:
                pass

    def get(self) -> bytes:
        if self._len == 0:
            raise ValueError("SecureBuffer zaten silindi.")
        return bytes(self._buf.raw[: self._len])

    def wipe(self):
        if self._len > 0:
            ctypes.memset(self._buf, 0, self._len)
            libc = self._get_libc()
            if libc:
                try:
                    libc.munlock(self._buf, ctypes.c_size_t(self._len))
                except Exception:
                    pass
            self._len = 0

    def __del__(self):
        self.wipe()


# ---------------------------------------------------------------------------
# Oturum içi şifreli kayıt deposu
# ---------------------------------------------------------------------------
class EncryptedStore:
    """
    Vault girişlerini bellekte şifreli saklar.

    - Hesap adı ve kullanıcı adı tablo gösterimi için plaintext tutulur.
    - Her parola, rastgele bir oturum anahtarıyla AES-256-GCM ile şifrelenir.
    - Oturum anahtarı SecureBuffer içinde mlock ile korunur.
    - Parolalar yalnızca kopyalama/düzenleme anında, tek tek, kısa süreliğine çözülür.
    """

    def __init__(self, entries: list):
        self._session_key = SecureBuffer(os.urandom(KEY_LEN))
        self._metadata: list[dict] = []        # [{hesap, kullanici}]
        self._enc_passwords: list[bytes] = []  # her parola için nonce+ciphertext
        for e in entries:
            self._append_raw(
                e.get("hesap", ""),
                e.get("kullanici", ""),
                e.get("sifre", ""),
            )

    # ---- İç yardımcılar ----

    def _append_raw(self, hesap: str, kullanici: str, sifre: str):
        self._metadata.append({"hesap": hesap, "kullanici": kullanici})
        self._enc_passwords.append(self._enc_pw(sifre))

    def _enc_pw(self, password: str) -> bytes:
        key = self._session_key.get()
        nonce = os.urandom(NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, password.encode("utf-8"), None)
        return nonce + ct

    def _dec_pw(self, blob: bytes) -> str:
        key = self._session_key.get()
        nonce = blob[:NONCE_LEN]
        ct = blob[NONCE_LEN:]
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")

    # ---- Dışa açık arayüz ----

    def count(self) -> int:
        return len(self._metadata)

    def get_display(self, index: int, show_password: bool) -> tuple:
        """Tablo satırı için (hesap, kullanici, sifre_veya_mask) döner."""
        m = self._metadata[index]
        if show_password:
            sifre = self._dec_pw(self._enc_passwords[index])
        else:
            sifre = MASK if self._enc_passwords[index] else ""
        return m["hesap"], m["kullanici"], sifre

    def get_password(self, index: int) -> str:
        """Yalnızca kopyalama için tek parola çözer."""
        return self._dec_pw(self._enc_passwords[index])

    def get_full_entry(self, index: int) -> dict:
        """Düzenleme dialogu için tam giriş döner (parola kısa süreliğine bellekte)."""
        m = self._metadata[index]
        return {
            "hesap": m["hesap"],
            "kullanici": m["kullanici"],
            "sifre": self._dec_pw(self._enc_passwords[index]),
        }

    def get_account_name(self, index: int) -> str:
        return self._metadata[index]["hesap"]

    def add(self, entry: dict):
        self._append_raw(
            entry.get("hesap", ""),
            entry.get("kullanici", ""),
            entry.get("sifre", ""),
        )

    def update(self, index: int, entry: dict):
        self._metadata[index] = {
            "hesap": entry.get("hesap", ""),
            "kullanici": entry.get("kullanici", ""),
        }
        self._enc_passwords[index] = self._enc_pw(entry.get("sifre", ""))

    def remove(self, index: int):
        self._metadata.pop(index)
        self._enc_passwords.pop(index)

    def get_entries_for_save(self) -> list:
        """
        Diske yazmak için tüm girişleri çözer.
        Dönen liste yalnızca encrypt_vault içinde kullanılmalı;
        encrypt_vault plaintext bytearray'i sıfırlar.
        """
        return [
            {
                "hesap": self._metadata[i]["hesap"],
                "kullanici": self._metadata[i]["kullanici"],
                "sifre": self._dec_pw(self._enc_passwords[i]),
            }
            for i in range(len(self._metadata))
        ]

    def wipe(self):
        self._session_key.wipe()
        self._metadata.clear()
        self._enc_passwords.clear()

    def __del__(self):
        self.wipe()


# ---------------------------------------------------------------------------
# Kripto katmanı
# ---------------------------------------------------------------------------
def derive_key(master_password: str, salt: bytes) -> bytes:
    """Master parola + salt -> 256-bit anahtar (Argon2id, 256 MB)."""
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME,
        memory_cost=ARGON_MEMORY,
        parallelism=ARGON_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def encrypt_vault(entries: list, key: bytes, salt: bytes) -> bytes:
    """
    Kasayı şifrele. Plaintext bytearray kullanılır ve şifrelemeden
    sonra sıfırlanır — Python GC'ye bırakılmaz.
    """
    nonce = os.urandom(NONCE_LEN)
    raw = json.dumps(entries, ensure_ascii=False).encode("utf-8")
    plaintext = bytearray(raw)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), None)
        return VAULT_MAGIC + bytes([VAULT_VERSION]) + salt + nonce + ciphertext
    finally:
        for i in range(len(plaintext)):
            plaintext[i] = 0


def decrypt_vault(blob: bytes, master_password: str):
    """
    Dosyayı çöz. Hem yeni (MAGIC+VERSİYON) hem eski format desteklenir.
    Plaintext bytearray JSON parse sonrası sıfırlanır.
    """
    if blob[:4] == VAULT_MAGIC:
        offset = 5
    else:
        offset = 0

    salt = blob[offset: offset + SALT_LEN]
    nonce = blob[offset + SALT_LEN: offset + SALT_LEN + NONCE_LEN]
    ciphertext = blob[offset + SALT_LEN + NONCE_LEN:]
    key = derive_key(master_password, salt)
    raw = bytearray(AESGCM(key).decrypt(nonce, ciphertext, None))
    try:
        entries = json.loads(raw.decode("utf-8"))
        return entries, key, salt
    finally:
        for i in range(len(raw)):
            raw[i] = 0


# ---------------------------------------------------------------------------
# Parola entropi kontrolü (zxcvbn)
# ---------------------------------------------------------------------------
def check_password_strength(password: str):
    """(ok: bool, mesaj: str) döner."""
    if ZXCVBN_AVAILABLE:
        result = _zxcvbn(password)
        score = result["score"]  # 0-4
        if score < 3:
            feedback = result["feedback"]
            warning = feedback.get("warning", "")
            suggestions = feedback.get("suggestions", [])
            msg = warning if warning else "Parola tahmin edilebilir veya çok zayıf."
            if suggestions:
                msg += "\n" + "\n".join(f"• {s}" for s in suggestions[:3])
            return False, msg
        return True, ""
    else:
        checks = [
            len(password) >= 12,
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
        if sum(checks) < 4:
            return False, (
                "Parola en az 12 karakter olmalı ve büyük/küçük harf,\n"
                "rakam ve özel karakter içermelidir.\n\n"
                "(Daha iyi analiz için: pip3 install zxcvbn)"
            )
        return True, ""


# ---------------------------------------------------------------------------
# Master parola giriş ekranı — brute-force korumalı
# ---------------------------------------------------------------------------
class UnlockDialog(tk.Toplevel):
    """
    Kasa varsa parola sorar; yoksa yeni kasa oluşturur.
    Yanlış denemelerde üstel gecikme: 2, 4, 8 ... 60 saniye.
    """

    def __init__(self, master, vault_exists: bool):
        super().__init__(master)
        self.vault_exists = vault_exists
        self.result = None
        self._fail_count = 0
        self._locked_until = 0.0

        self.title("Şifre Kasası")
        self.resizable(False, False)
        self.configure(padx=24, pady=20)
        self.grab_set()

        if vault_exists:
            head = "Kasanı açmak için master parolanı gir"
        else:
            head = "Yeni kasa oluştur — bir master parola belirle\n(unutursan kurtarılamaz!)"

        ttk.Label(self, text=head, justify="center").grid(
            row=0, column=0, columnspan=2, pady=(0, 14))

        ttk.Label(self, text="Master parola:").grid(row=1, column=0, sticky="e", pady=4)
        self.pw1 = ttk.Entry(self, show="•", width=28)
        self.pw1.grid(row=1, column=1, pady=4)
        self.pw1.focus_set()

        if not vault_exists:
            ttk.Label(self, text="Tekrar:").grid(row=2, column=0, sticky="e", pady=4)
            self.pw2 = ttk.Entry(self, show="•", width=28)
            self.pw2.grid(row=2, column=1, pady=4)

        self._status_var = tk.StringVar()
        ttk.Label(self, textvariable=self._status_var,
                  foreground="red", wraplength=300, justify="center").grid(
            row=3, column=0, columnspan=2, pady=4)

        self._btn = ttk.Button(
            self, text="Aç" if vault_exists else "Oluştur", command=self._submit)
        self._btn.grid(row=4, column=0, columnspan=2, pady=(14, 0), sticky="ew")

        self.bind("<Return>", lambda e: self._submit())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _backoff_seconds(self) -> float:
        if self._fail_count < 2:
            return 0.0
        return float(min(2 ** (self._fail_count - 1), 60))

    def _submit(self):
        remaining = self._locked_until - time.time()
        if remaining > 0:
            self._status_var.set(f"Çok fazla hatalı deneme. {remaining:.0f} saniye bekle.")
            return

        pw = self.pw1.get()
        if not pw:
            messagebox.showwarning("Uyarı", "Parola boş olamaz.", parent=self)
            return

        if self.vault_exists:
            self._btn.config(state="disabled")
            self._status_var.set("Doğrulanıyor…")
            self.update()
            try:
                with open(VAULT_FILE, "rb") as f:
                    blob = f.read()
                entries, key, salt = decrypt_vault(blob, pw)
                self.result = (entries, key, salt)
                self._btn.config(state="normal")
                self.destroy()
            except (InvalidTag, ValueError):
                self._fail_count += 1
                delay = self._backoff_seconds()
                self._locked_until = time.time() + delay
                self._btn.config(state="normal")
                if delay > 0:
                    self._status_var.set(
                        f"Yanlış parola — {delay:.0f} sn bekleniyor. "
                        f"({self._fail_count}. deneme)")
                else:
                    self._status_var.set(f"Yanlış parola. ({self._fail_count}. deneme)")
                self.pw1.delete(0, tk.END)
                self.pw1.focus_set()
        else:
            if pw != self.pw2.get():
                messagebox.showwarning("Uyarı", "Parolalar uyuşmuyor.", parent=self)
                return

            ok, feedback = check_password_strength(pw)
            if not ok:
                if not messagebox.askyesno(
                        "Zayıf Parola",
                        f"{feedback}\n\nYine de devam edeyim mi?",
                        parent=self):
                    return

            self._btn.config(state="disabled")
            self._status_var.set("Anahtar türetiliyor…")
            self.update()
            salt = os.urandom(SALT_LEN)
            key = derive_key(pw, salt)
            self.result = ([], key, salt)
            self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


# ---------------------------------------------------------------------------
# Kayıt ekle / düzenle ekranı
# ---------------------------------------------------------------------------
class EntryDialog(tk.Toplevel):
    def __init__(self, master, title, entry=None):
        super().__init__(master)
        self.result = None
        self.title(title)
        self.resizable(False, False)
        self.configure(padx=24, pady=20)
        self.grab_set()

        entry = entry or {"hesap": "", "kullanici": "", "sifre": ""}

        ttk.Label(self, text="Hesap:").grid(row=0, column=0, sticky="e", pady=4)
        self.e_hesap = ttk.Entry(self, width=32)
        self.e_hesap.grid(row=0, column=1, pady=4)
        self.e_hesap.insert(0, entry["hesap"])

        ttk.Label(self, text="Kullanıcı adı:").grid(row=1, column=0, sticky="e", pady=4)
        self.e_kullanici = ttk.Entry(self, width=32)
        self.e_kullanici.grid(row=1, column=1, pady=4)
        self.e_kullanici.insert(0, entry["kullanici"])

        ttk.Label(self, text="Şifre:").grid(row=2, column=0, sticky="e", pady=4)
        self.e_sifre = ttk.Entry(self, width=32, show="•")
        self.e_sifre.grid(row=2, column=1, pady=4)
        self.e_sifre.insert(0, entry["sifre"])

        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Şifreyi göster", variable=self.show_var,
                        command=self._toggle).grid(row=3, column=1, sticky="w")

        ttk.Button(self, text="Kaydet", command=self._submit).grid(
            row=4, column=0, columnspan=2, pady=(14, 0), sticky="ew")

        self.e_hesap.focus_set()
        self.bind("<Return>", lambda e: self._submit())

    def _toggle(self):
        self.e_sifre.config(show="" if self.show_var.get() else "•")

    def _submit(self):
        hesap = self.e_hesap.get().strip()
        if not hesap:
            messagebox.showwarning("Uyarı", "Hesap adı boş olamaz.", parent=self)
            return
        self.result = {
            "hesap": hesap,
            "kullanici": self.e_kullanici.get().strip(),
            "sifre": self.e_sifre.get(),
        }
        self.destroy()


# ---------------------------------------------------------------------------
# Ana pencere
# ---------------------------------------------------------------------------
class VaultApp:
    def __init__(self, root: tk.Tk, entries: list, key: bytes, salt: bytes):
        self.root = root
        self._secure_key = SecureBuffer(key)   # disk anahtarı mlock'lu
        self.salt = salt
        self.store = EncryptedStore(entries)   # parolalar oturum anahtarıyla şifreli
        self.show_passwords = False
        self._clip_token = None
        self._lock_token = None

        root.title("Şifre Kasası")
        root.geometry("680x440")
        root.minsize(560, 340)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        bar = ttk.Frame(root, padding=(10, 8))
        bar.pack(fill="x")
        ttk.Button(bar, text="+ Ekle",          command=self.add_entry).pack(side="left")
        ttk.Button(bar, text="Düzenle",         command=self.edit_entry).pack(side="left", padx=6)
        ttk.Button(bar, text="Sil",             command=self.delete_entry).pack(side="left")
        ttk.Button(bar, text="Şifreyi Kopyala", command=self.copy_password).pack(side="left", padx=6)
        ttk.Button(bar, text="🔒 Kilitle",      command=self._lock).pack(side="left", padx=6)
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Şifreleri göster", variable=self.show_var,
                        command=self.toggle_show).pack(side="right")

        cols = ("hesap", "kullanici", "sifre")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("hesap",     text="Hesap")
        self.tree.heading("kullanici", text="Kullanıcı adı")
        self.tree.heading("sifre",     text="Şifre")
        self.tree.column("hesap",     width=200, anchor="w")
        self.tree.column("kullanici", width=240, anchor="w")
        self.tree.column("sifre",     width=200, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.tree.bind("<Double-1>", lambda e: self.edit_entry())

        self._status_var = tk.StringVar()
        ttk.Label(root, textvariable=self._status_var, foreground="#888").pack(pady=(0, 8))

        self._setup_auto_lock()
        self.refresh()

    # ---- Otomatik kilitleme ----

    def _setup_auto_lock(self):
        self._reset_lock_timer()
        self.root.bind_all("<KeyPress>",    self._on_activity, add="+")
        self.root.bind_all("<ButtonPress>", self._on_activity, add="+")
        self.root.bind_all("<Motion>",      self._on_activity, add="+")

    def _on_activity(self, *_):
        self._reset_lock_timer()

    def _reset_lock_timer(self):
        if self._lock_token:
            self.root.after_cancel(self._lock_token)
        self._lock_token = self.root.after(LOCK_TIMEOUT_MS, self._lock)
        mins = LOCK_TIMEOUT_MS // 60_000
        self._status_var.set(
            f"Çift tıkla = düzenle  •  pano 15 sn temizlenir  •  "
            f"{mins} dk hareketsizlikte kilitlenir")

    def _lock(self):
        """Oturum anahtarını ve tüm parolaları bellekten sil; yeniden giriş iste."""
        if self._lock_token:
            self.root.after_cancel(self._lock_token)
            self._lock_token = None

        self.store.wipe()
        self.tree.delete(*self.tree.get_children())

        self.root.withdraw()
        dlg = UnlockDialog(self.root, True)
        self.root.wait_window(dlg)

        if dlg.result is None:
            self._on_close()
            return

        entries, key, salt = dlg.result
        self._secure_key = SecureBuffer(key)
        self.salt = salt
        self.store = EncryptedStore(entries)
        self.root.deiconify()
        self._setup_auto_lock()
        self.refresh()

    def _on_close(self):
        self.store.wipe()
        if self._secure_key:
            self._secure_key.wipe()
        self.root.destroy()

    # ---- Tablo ----

    def refresh(self):
        sel = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for i in range(self.store.count()):
            hesap, kullanici, sifre = self.store.get_display(i, self.show_passwords)
            self.tree.insert("", "end", iid=str(i), values=(hesap, kullanici, sifre))
        if sel and sel[0] in self.tree.get_children():
            self.tree.selection_set(sel)

    def toggle_show(self):
        self.show_passwords = self.show_var.get()
        self.refresh()

    def _selected_index(self):
        sel = self.tree.selection()
        return int(sel[0]) if sel else None

    # ---- CRUD ----

    def add_entry(self):
        dlg = EntryDialog(self.root, "Yeni Kayıt")
        self.root.wait_window(dlg)
        if dlg.result:
            self.store.add(dlg.result)
            self.save()
            self.refresh()

    def edit_entry(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Bilgi", "Önce bir satır seç.")
            return
        dlg = EntryDialog(self.root, "Kaydı Düzenle", self.store.get_full_entry(idx))
        self.root.wait_window(dlg)
        if dlg.result:
            self.store.update(idx, dlg.result)
            self.save()
            self.refresh()

    def delete_entry(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Bilgi", "Önce bir satır seç.")
            return
        if messagebox.askyesno("Sil", f"'{self.store.get_account_name(idx)}' silinsin mi?"):
            self.store.remove(idx)
            self.save()
            self.refresh()

    # ---- Pano ----

    def copy_password(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Bilgi", "Önce bir satır seç.")
            return
        pw = self.store.get_password(idx)   # tek parola, kısa süreliğine çözülür
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        if self._clip_token:
            self.root.after_cancel(self._clip_token)
        self._clip_token = self.root.after(
            CLIPBOARD_CLEAR_MS, lambda: self._clear_clip(pw))

    def _clear_clip(self, expected):
        try:
            if self.root.clipboard_get() == expected:
                self.root.clipboard_clear()
                self.root.clipboard_append("")
        except tk.TclError:
            pass
        self._clip_token = None

    # ---- Diske yaz ----

    def save(self):
        entries = self.store.get_entries_for_save()
        key = self._secure_key.get()
        blob = encrypt_vault(entries, key, self.salt)  # plaintext bytearray içinde sıfırlanır
        tmp = VAULT_FILE + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.replace(tmp, VAULT_FILE)
        try:
            os.chmod(VAULT_FILE, 0o600)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Başlat
# ---------------------------------------------------------------------------
def main():
    root = tk.Tk()
    root.withdraw()

    vault_exists = os.path.exists(VAULT_FILE)
    dlg = UnlockDialog(root, vault_exists)
    root.wait_window(dlg)

    if dlg.result is None:
        root.destroy()
        return

    entries, key, salt = dlg.result
    root.deiconify()
    VaultApp(root, entries, key, salt)
    root.mainloop()


if __name__ == "__main__":
    main()
