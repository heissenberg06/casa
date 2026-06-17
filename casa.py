#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Şifre Kasası - Offline parola yöneticisi (macOS)

Güvenlik mimarisi:
  - Master parola hiçbir yere kaydedilmez.
  - Master parola + rastgele salt  -> Argon2id -> 256-bit anahtar.
  - Tüm kasa AES-256-GCM ile şifrelenir (gizlilik + bütünlük).
  - Diskte sadece:  salt | nonce | şifreli veri (+auth tag) durur.
    Bunların hiçbiri master parola olmadan işe yaramaz.

Kurulum:
  pip3 install argon2-cffi cryptography

Çalıştırma:
  python3 sifre_kasasi.py
"""

import os
import json
import tkinter as tk
from tkinter import ttk, messagebox

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Ayarlar
# ---------------------------------------------------------------------------
VAULT_FILE = os.path.join(os.path.expanduser("~"), ".sifre_kasasi.dat")

# Argon2id parametreleri (yüksek = brute-force'a daha dirençli, ama daha yavaş)
ARGON_TIME = 4            # iterasyon sayısı
ARGON_MEMORY = 128 * 1024  # KiB cinsinden = 128 MB
ARGON_PARALLELISM = 4
KEY_LEN = 32             # 256-bit anahtar
SALT_LEN = 16
NONCE_LEN = 12

CLIPBOARD_CLEAR_MS = 20000  # panoyu 20 sn sonra temizle
MASK = "•" * 8              # şifre gizliyken gösterilen maske (uzunluk sızdırmaz)


# ---------------------------------------------------------------------------
# Kripto katmanı
# ---------------------------------------------------------------------------
def derive_key(master_password: str, salt: bytes) -> bytes:
    """Master parola + salt -> 256-bit anahtar (Argon2id)."""
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
    """Kasayı şifrele. Her kayıtta YENİ nonce üretilir (GCM kuralı)."""
    nonce = os.urandom(NONCE_LEN)
    plaintext = json.dumps(entries, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt_vault(blob: bytes, master_password: str):
    """
    Dosyayı çöz. Doğru parola + sağlam dosya ise (entries, key, salt) döner.
    Yanlış parola veya oynanmış dosyada InvalidTag fırlatır.
    """
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN:]
    key = derive_key(master_password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)  # yanlışsa hata
    entries = json.loads(plaintext.decode("utf-8"))
    return entries, key, salt


# ---------------------------------------------------------------------------
# Master parola giriş ekranı
# ---------------------------------------------------------------------------
class UnlockDialog(tk.Toplevel):
    """Kasa varsa parola sorar, yoksa yeni kasa için iki kez sorar."""

    def __init__(self, master, vault_exists: bool):
        super().__init__(master)
        self.vault_exists = vault_exists
        self.result = None  # (entries, key, salt)

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

        btn = ttk.Button(self, text="Aç" if vault_exists else "Oluştur",
                         command=self._submit)
        btn.grid(row=3, column=0, columnspan=2, pady=(14, 0), sticky="ew")

        self.bind("<Return>", lambda e: self._submit())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _submit(self):
        pw = self.pw1.get()
        if not pw:
            messagebox.showwarning("Uyarı", "Parola boş olamaz.", parent=self)
            return

        if self.vault_exists:
            try:
                with open(VAULT_FILE, "rb") as f:
                    blob = f.read()
                entries, key, salt = decrypt_vault(blob, pw)
                self.result = (entries, key, salt)
                self.destroy()
            except (InvalidTag, ValueError):
                messagebox.showerror("Hata", "Parola yanlış (ya da dosya bozuk).",
                                     parent=self)
                self.pw1.delete(0, tk.END)
                self.pw1.focus_set()
        else:
            if pw != self.pw2.get():
                messagebox.showwarning("Uyarı", "Parolalar uyuşmuyor.", parent=self)
                return
            if len(pw) < 8:
                if not messagebox.askyesno(
                        "Zayıf parola",
                        "Parolan 8 karakterden kısa. Yine de devam edeyim mi?",
                        parent=self):
                    return
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
    def __init__(self, root, entries, key, salt):
        self.root = root
        self.entries = entries
        self.key = key          # oturum boyunca bellekte tutulan anahtar
        self.salt = salt
        self.show_passwords = False
        self._clip_token = None

        root.title("Şifre Kasası")
        root.geometry("680x420")
        root.minsize(560, 320)

        # Üst butonlar
        bar = ttk.Frame(root, padding=(10, 8))
        bar.pack(fill="x")
        ttk.Button(bar, text="+ Ekle", command=self.add_entry).pack(side="left")
        ttk.Button(bar, text="Düzenle", command=self.edit_entry).pack(side="left", padx=6)
        ttk.Button(bar, text="Sil", command=self.delete_entry).pack(side="left")
        ttk.Button(bar, text="Şifreyi Kopyala", command=self.copy_password).pack(side="left", padx=6)
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Şifreleri göster", variable=self.show_var,
                        command=self.toggle_show).pack(side="right")

        # Tablo
        cols = ("hesap", "kullanici", "sifre")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("hesap", text="Hesap")
        self.tree.heading("kullanici", text="Kullanıcı adı")
        self.tree.heading("sifre", text="Şifre")
        self.tree.column("hesap", width=200, anchor="w")
        self.tree.column("kullanici", width=240, anchor="w")
        self.tree.column("sifre", width=200, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.tree.bind("<Double-1>", lambda e: self.edit_entry())

        ttk.Label(root, text="Çift tıkla = düzenle  •  pano 20 sn sonra otomatik temizlenir",
                  foreground="#888").pack(pady=(0, 8))

        self.refresh()

    # ---- tablo yenileme ----
    def refresh(self):
        sel = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for i, e in enumerate(self.entries):
            sifre = e["sifre"] if self.show_passwords else (MASK if e["sifre"] else "")
            self.tree.insert("", "end", iid=str(i),
                             values=(e["hesap"], e["kullanici"], sifre))
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
            self.entries.append(dlg.result)
            self.save()
            self.refresh()

    def edit_entry(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Bilgi", "Önce bir satır seç.")
            return
        dlg = EntryDialog(self.root, "Kaydı Düzenle", self.entries[idx])
        self.root.wait_window(dlg)
        if dlg.result:
            self.entries[idx] = dlg.result
            self.save()
            self.refresh()

    def delete_entry(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Bilgi", "Önce bir satır seç.")
            return
        if messagebox.askyesno("Sil", f"'{self.entries[idx]['hesap']}' silinsin mi?"):
            self.entries.pop(idx)
            self.save()
            self.refresh()

    # ---- pano ----
    def copy_password(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Bilgi", "Önce bir satır seç.")
            return
        pw = self.entries[idx]["sifre"]
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        # önceki temizleme zamanlayıcısını iptal et, yenisini kur
        if self._clip_token:
            self.root.after_cancel(self._clip_token)
        self._clip_token = self.root.after(CLIPBOARD_CLEAR_MS, lambda: self._clear_clip(pw))

    def _clear_clip(self, expected):
        try:
            if self.root.clipboard_get() == expected:
                self.root.clipboard_clear()
                self.root.clipboard_append("")
        except tk.TclError:
            pass
        self._clip_token = None

    # ---- diske yaz ----
    def save(self):
        blob = encrypt_vault(self.entries, self.key, self.salt)
        # önce geçici dosyaya yaz, sonra taşı (yazma sırasında çökerse veri kaybı olmasın)
        tmp = VAULT_FILE + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.replace(tmp, VAULT_FILE)
        try:
            os.chmod(VAULT_FILE, 0o600)  # sadece sahibi okuyup yazabilsin
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Başlat
# ---------------------------------------------------------------------------
def main():
    root = tk.Tk()
    root.withdraw()  # ana pencereyi parola girilene kadar gizle

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