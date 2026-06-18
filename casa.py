#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Password Vault — Offline password manager (macOS)

Security architecture:
  - Master password is never stored anywhere.
  - Master password + random salt -> Argon2id (256 MB) -> 256-bit disk key.
  - Entire vault is encrypted with AES-256-GCM (confidentiality + integrity).
  - On disk: MAGIC | VERSION | salt | nonce | ciphertext.

  Memory security:
  - Disk key and session key are held in mlock-pinned SecureBuffers,
    zeroed with ctypes.memset on lock/close.
  - After unlock, passwords are re-encrypted in-memory with a random
    session key (EncryptedStore); they never sit as plaintext Python strings.
  - Only account names and usernames are kept in plaintext for display.
  - Plaintext bytearray is zeroed after disk encryption.
  - 5-minute inactivity auto-lock; manual lock button.
  - Exponential back-off on wrong password attempts.
  - zxcvbn password-strength evaluation on vault creation.
  - .tmp file created with 0o600 permissions before atomic rename.

Setup:
  pip3 install argon2-cffi cryptography zxcvbn

Run:
  python3 casa.py
"""

import os
import json
import time
import sys
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
# i18n
# ---------------------------------------------------------------------------
TRANSLATIONS: dict[str, dict[str, str]] = {
    'en': {
        'app_title':          'Password Vault',
        'unlock_prompt':      'Enter your master password to unlock the vault',
        'create_prompt':      'Create new vault — set a master password\n(if forgotten, it cannot be recovered!)',
        'label_master_pw':    'Master password:',
        'label_confirm':      'Confirm:',
        'btn_unlock':         'Unlock',
        'btn_create':         'Create',
        'btn_save':           'Save',
        'btn_add':            '+ Add',
        'btn_edit':           'Edit',
        'btn_delete':         'Delete',
        'btn_copy_pw':        'Copy Password',
        'btn_lock':           '🔒 Lock',
        'chk_show_passwords': 'Show passwords',
        'chk_show_password':  'Show password',
        'col_account':        'Account',
        'col_username':       'Username',
        'col_password':       'Password',
        'dlg_new_entry':      'New Entry',
        'dlg_edit_entry':     'Edit Entry',
        'label_account':      'Account:',
        'label_username':     'Username:',
        'label_password':     'Password:',
        'label_language':     'Language:',
        'verifying':          'Verifying…',
        'deriving_key':       'Deriving key…',
        'warn_empty_pw':      'Password cannot be empty.',
        'warn_no_match':      'Passwords do not match.',
        'warn_empty_account': 'Account name cannot be empty.',
        'warn_select_row':    'Please select a row first.',
        'err_wrong_pw':       'Wrong password (or file is corrupted).',
        'title_warning':      'Warning',
        'title_error':        'Error',
        'title_info':         'Info',
        'title_delete':       'Delete',
        'title_weak_pw':      'Weak Password',
        'confirm_delete':     "Delete '{account}'?",
        'confirm_weak_pw':    '{feedback}\n\nProceed anyway?',
        'backoff_locked':     'Too many failed attempts. Wait {n} seconds.',
        'backoff_waiting':    'Wrong password — waiting {n} s. (attempt {count})',
        'backoff_wrong':      'Wrong password. (attempt {count})',
        'pw_too_weak':        'Password is predictable or too weak.',
        'pw_weak_fallback':   (
            'Password must be at least 12 characters and contain '
            'uppercase, lowercase, digits, and special characters.\n\n'
            '(Better analysis: pip3 install zxcvbn)'
        ),
        'status_bar': (
            'Double-click to edit  •  clipboard clears in 15 s  •  '
            'auto-locks in {mins} min'
        ),
    },
    'es': {
        'app_title':          'Bóveda de Contraseñas',
        'unlock_prompt':      'Introduce tu contraseña maestra para desbloquear',
        'create_prompt':      'Crear nueva bóveda — establece una contraseña maestra\n(¡si la olvidas, no se puede recuperar!)',
        'label_master_pw':    'Contraseña maestra:',
        'label_confirm':      'Confirmar:',
        'btn_unlock':         'Desbloquear',
        'btn_create':         'Crear',
        'btn_save':           'Guardar',
        'btn_add':            '+ Añadir',
        'btn_edit':           'Editar',
        'btn_delete':         'Eliminar',
        'btn_copy_pw':        'Copiar Contraseña',
        'btn_lock':           '🔒 Bloquear',
        'chk_show_passwords': 'Mostrar contraseñas',
        'chk_show_password':  'Mostrar contraseña',
        'col_account':        'Cuenta',
        'col_username':       'Usuario',
        'col_password':       'Contraseña',
        'dlg_new_entry':      'Nueva Entrada',
        'dlg_edit_entry':     'Editar Entrada',
        'label_account':      'Cuenta:',
        'label_username':     'Usuario:',
        'label_password':     'Contraseña:',
        'label_language':     'Idioma:',
        'verifying':          'Verificando…',
        'deriving_key':       'Derivando clave…',
        'warn_empty_pw':      'La contraseña no puede estar vacía.',
        'warn_no_match':      'Las contraseñas no coinciden.',
        'warn_empty_account': 'El nombre de cuenta no puede estar vacío.',
        'warn_select_row':    'Por favor, selecciona una fila primero.',
        'err_wrong_pw':       'Contraseña incorrecta (o archivo dañado).',
        'title_warning':      'Advertencia',
        'title_error':        'Error',
        'title_info':         'Información',
        'title_delete':       'Eliminar',
        'title_weak_pw':      'Contraseña Débil',
        'confirm_delete':     "¿Eliminar '{account}'?",
        'confirm_weak_pw':    '{feedback}\n\n¿Continuar de todas formas?',
        'backoff_locked':     'Demasiados intentos fallidos. Espera {n} segundos.',
        'backoff_waiting':    'Contraseña incorrecta — esperando {n} s. (intento {count})',
        'backoff_wrong':      'Contraseña incorrecta. (intento {count})',
        'pw_too_weak':        'La contraseña es predecible o demasiado débil.',
        'pw_weak_fallback':   (
            'La contraseña debe tener al menos 12 caracteres y contener '
            'mayúsculas, minúsculas, dígitos y caracteres especiales.\n\n'
            '(Mejor análisis: pip3 install zxcvbn)'
        ),
        'status_bar': (
            'Doble clic para editar  •  portapapeles en 15 s  •  '
            'bloqueo auto en {mins} min'
        ),
    },
    'de': {
        'app_title':          'Passwort-Tresor',
        'unlock_prompt':      'Masterpasswort eingeben zum Entsperren',
        'create_prompt':      'Neuen Tresor erstellen — Masterpasswort festlegen\n(Bei Verlust nicht wiederherstellbar!)',
        'label_master_pw':    'Masterpasswort:',
        'label_confirm':      'Bestätigen:',
        'btn_unlock':         'Entsperren',
        'btn_create':         'Erstellen',
        'btn_save':           'Speichern',
        'btn_add':            '+ Hinzufügen',
        'btn_edit':           'Bearbeiten',
        'btn_delete':         'Löschen',
        'btn_copy_pw':        'Passwort kopieren',
        'btn_lock':           '🔒 Sperren',
        'chk_show_passwords': 'Passwörter anzeigen',
        'chk_show_password':  'Passwort anzeigen',
        'col_account':        'Konto',
        'col_username':       'Benutzername',
        'col_password':       'Passwort',
        'dlg_new_entry':      'Neuer Eintrag',
        'dlg_edit_entry':     'Eintrag bearbeiten',
        'label_account':      'Konto:',
        'label_username':     'Benutzername:',
        'label_password':     'Passwort:',
        'label_language':     'Sprache:',
        'verifying':          'Wird überprüft…',
        'deriving_key':       'Schlüssel wird abgeleitet…',
        'warn_empty_pw':      'Passwort darf nicht leer sein.',
        'warn_no_match':      'Passwörter stimmen nicht überein.',
        'warn_empty_account': 'Kontoname darf nicht leer sein.',
        'warn_select_row':    'Bitte zuerst eine Zeile auswählen.',
        'err_wrong_pw':       'Falsches Passwort (oder Datei beschädigt).',
        'title_warning':      'Warnung',
        'title_error':        'Fehler',
        'title_info':         'Info',
        'title_delete':       'Löschen',
        'title_weak_pw':      'Schwaches Passwort',
        'confirm_delete':     "'{account}' löschen?",
        'confirm_weak_pw':    '{feedback}\n\nTrotzdem fortfahren?',
        'backoff_locked':     'Zu viele Fehlversuche. Warte {n} Sekunden.',
        'backoff_waiting':    'Falsches Passwort — warte {n} s. (Versuch {count})',
        'backoff_wrong':      'Falsches Passwort. (Versuch {count})',
        'pw_too_weak':        'Das Passwort ist vorhersehbar oder zu schwach.',
        'pw_weak_fallback':   (
            'Das Passwort muss mindestens 12 Zeichen haben und '
            'Groß-/Kleinbuchstaben, Ziffern und Sonderzeichen enthalten.\n\n'
            '(Bessere Analyse: pip3 install zxcvbn)'
        ),
        'status_bar': (
            'Doppelklick zum Bearbeiten  •  Zwischenablage in 15 s  •  '
            'Autosperre in {mins} Min'
        ),
    },
    'zh': {
        'app_title':          '密码保险库',
        'unlock_prompt':      '请输入主密码以解锁',
        'create_prompt':      '创建新保险库 — 设置主密码\n（若忘记则无法恢复！）',
        'label_master_pw':    '主密码：',
        'label_confirm':      '确认：',
        'btn_unlock':         '解锁',
        'btn_create':         '创建',
        'btn_save':           '保存',
        'btn_add':            '+ 添加',
        'btn_edit':           '编辑',
        'btn_delete':         '删除',
        'btn_copy_pw':        '复制密码',
        'btn_lock':           '🔒 锁定',
        'chk_show_passwords': '显示密码',
        'chk_show_password':  '显示密码',
        'col_account':        '账户',
        'col_username':       '用户名',
        'col_password':       '密码',
        'dlg_new_entry':      '新建条目',
        'dlg_edit_entry':     '编辑条目',
        'label_account':      '账户：',
        'label_username':     '用户名：',
        'label_password':     '密码：',
        'label_language':     '语言：',
        'verifying':          '验证中…',
        'deriving_key':       '正在派生密钥…',
        'warn_empty_pw':      '密码不能为空。',
        'warn_no_match':      '两次密码不一致。',
        'warn_empty_account': '账户名不能为空。',
        'warn_select_row':    '请先选择一行。',
        'err_wrong_pw':       '密码错误（或文件已损坏）。',
        'title_warning':      '警告',
        'title_error':        '错误',
        'title_info':         '信息',
        'title_delete':       '删除',
        'title_weak_pw':      '密码强度不足',
        'confirm_delete':     '删除"{account}"？',
        'confirm_weak_pw':    '{feedback}\n\n是否继续？',
        'backoff_locked':     '尝试次数过多，请等待 {n} 秒。',
        'backoff_waiting':    '密码错误 — 等待 {n} 秒。（第 {count} 次尝试）',
        'backoff_wrong':      '密码错误。（第 {count} 次尝试）',
        'pw_too_weak':        '密码过于简单或可预测。',
        'pw_weak_fallback':   (
            '密码至少需要12个字符，并包含大小写字母、数字和特殊字符。\n\n'
            '（更好的分析：pip3 install zxcvbn）'
        ),
        'status_bar': '双击编辑  •  剪贴板15秒后清除  •  {mins}分钟后自动锁定',
    },
    'ja': {
        'app_title':          'パスワード保管庫',
        'unlock_prompt':      'マスターパスワードを入力してロック解除',
        'create_prompt':      '新しい保管庫を作成 — マスターパスワードを設定\n（忘れると回復できません！）',
        'label_master_pw':    'マスターパスワード：',
        'label_confirm':      '確認：',
        'btn_unlock':         'ロック解除',
        'btn_create':         '作成',
        'btn_save':           '保存',
        'btn_add':            '+ 追加',
        'btn_edit':           '編集',
        'btn_delete':         '削除',
        'btn_copy_pw':        'パスワードをコピー',
        'btn_lock':           '🔒 ロック',
        'chk_show_passwords': 'パスワードを表示',
        'chk_show_password':  'パスワードを表示',
        'col_account':        'アカウント',
        'col_username':       'ユーザー名',
        'col_password':       'パスワード',
        'dlg_new_entry':      '新規エントリ',
        'dlg_edit_entry':     'エントリを編集',
        'label_account':      'アカウント：',
        'label_username':     'ユーザー名：',
        'label_password':     'パスワード：',
        'label_language':     '言語：',
        'verifying':          '確認中…',
        'deriving_key':       '鍵を導出中…',
        'warn_empty_pw':      'パスワードを入力してください。',
        'warn_no_match':      'パスワードが一致しません。',
        'warn_empty_account': 'アカウント名を入力してください。',
        'warn_select_row':    '先に行を選択してください。',
        'err_wrong_pw':       'パスワードが違います（またはファイルが破損しています）。',
        'title_warning':      '警告',
        'title_error':        'エラー',
        'title_info':         '情報',
        'title_delete':       '削除',
        'title_weak_pw':      '弱いパスワード',
        'confirm_delete':     '「{account}」を削除しますか？',
        'confirm_weak_pw':    '{feedback}\n\n続行しますか？',
        'backoff_locked':     '試行回数が多すぎます。{n} 秒お待ちください。',
        'backoff_waiting':    'パスワードが違います — {n} 秒待機中。（試行 {count} 回目）',
        'backoff_wrong':      'パスワードが違います。（試行 {count} 回目）',
        'pw_too_weak':        'パスワードが予測可能または弱すぎます。',
        'pw_weak_fallback':   (
            'パスワードは12文字以上で、大文字・小文字・数字・特殊文字を含む必要があります。\n\n'
            '（より良い分析には: pip3 install zxcvbn）'
        ),
        'status_bar': (
            'ダブルクリックで編集  •  クリップボードは15秒後クリア  •  '
            '{mins}分後に自動ロック'
        ),
    },
    'fr': {
        'app_title':          'Coffre-fort de Mots de Passe',
        'unlock_prompt':      'Entrez votre mot de passe maître pour déverrouiller',
        'create_prompt':      'Créer un nouveau coffre — définissez un mot de passe maître\n(en cas d\'oubli, il est irrécupérable !)',
        'label_master_pw':    'Mot de passe maître :',
        'label_confirm':      'Confirmer :',
        'btn_unlock':         'Déverrouiller',
        'btn_create':         'Créer',
        'btn_save':           'Enregistrer',
        'btn_add':            '+ Ajouter',
        'btn_edit':           'Modifier',
        'btn_delete':         'Supprimer',
        'btn_copy_pw':        'Copier le mot de passe',
        'btn_lock':           '🔒 Verrouiller',
        'chk_show_passwords': 'Afficher les mots de passe',
        'chk_show_password':  'Afficher le mot de passe',
        'col_account':        'Compte',
        'col_username':       'Utilisateur',
        'col_password':       'Mot de passe',
        'dlg_new_entry':      'Nouvelle Entrée',
        'dlg_edit_entry':     "Modifier l'Entrée",
        'label_account':      'Compte :',
        'label_username':     'Utilisateur :',
        'label_password':     'Mot de passe :',
        'label_language':     'Langue :',
        'verifying':          'Vérification…',
        'deriving_key':       'Dérivation de la clé…',
        'warn_empty_pw':      'Le mot de passe ne peut pas être vide.',
        'warn_no_match':      'Les mots de passe ne correspondent pas.',
        'warn_empty_account': 'Le nom du compte ne peut pas être vide.',
        'warn_select_row':    'Veuillez d\'abord sélectionner une ligne.',
        'err_wrong_pw':       'Mot de passe incorrect (ou fichier corrompu).',
        'title_warning':      'Avertissement',
        'title_error':        'Erreur',
        'title_info':         'Information',
        'title_delete':       'Supprimer',
        'title_weak_pw':      'Mot de Passe Faible',
        'confirm_delete':     '« {account} » supprimer ?',
        'confirm_weak_pw':    '{feedback}\n\nContinuer quand même ?',
        'backoff_locked':     'Trop de tentatives. Attendez {n} secondes.',
        'backoff_waiting':    'Mot de passe incorrect — attente {n} s. (tentative {count})',
        'backoff_wrong':      'Mot de passe incorrect. (tentative {count})',
        'pw_too_weak':        'Le mot de passe est prévisible ou trop faible.',
        'pw_weak_fallback':   (
            'Le mot de passe doit comporter au moins 12 caractères et contenir '
            'des majuscules, minuscules, chiffres et caractères spéciaux.\n\n'
            '(Meilleure analyse : pip3 install zxcvbn)'
        ),
        'status_bar': (
            'Double-clic pour modifier  •  presse-papiers vidé en 15 s  •  '
            'verrouillage auto dans {mins} min'
        ),
    },
    'hi': {
        'app_title':          'पासवर्ड वॉल्ट',
        'unlock_prompt':      'वॉल्ट खोलने के लिए मास्टर पासवर्ड दर्ज करें',
        'create_prompt':      'नया वॉल्ट बनाएं — मास्टर पासवर्ड सेट करें\n(भूल जाने पर पुनर्प्राप्त नहीं किया जा सकता!)',
        'label_master_pw':    'मास्टर पासवर्ड:',
        'label_confirm':      'पुष्टि करें:',
        'btn_unlock':         'खोलें',
        'btn_create':         'बनाएं',
        'btn_save':           'सहेजें',
        'btn_add':            '+ जोड़ें',
        'btn_edit':           'संपादित करें',
        'btn_delete':         'हटाएं',
        'btn_copy_pw':        'पासवर्ड कॉपी करें',
        'btn_lock':           '🔒 लॉक करें',
        'chk_show_passwords': 'पासवर्ड दिखाएं',
        'chk_show_password':  'पासवर्ड दिखाएं',
        'col_account':        'खाता',
        'col_username':       'उपयोगकर्ता नाम',
        'col_password':       'पासवर्ड',
        'dlg_new_entry':      'नई प्रविष्टि',
        'dlg_edit_entry':     'प्रविष्टि संपादित करें',
        'label_account':      'खाता:',
        'label_username':     'उपयोगकर्ता नाम:',
        'label_password':     'पासवर्ड:',
        'label_language':     'भाषा:',
        'verifying':          'जाँच हो रही है…',
        'deriving_key':       'कुंजी बनाई जा रही है…',
        'warn_empty_pw':      'पासवर्ड खाली नहीं हो सकता।',
        'warn_no_match':      'पासवर्ड मेल नहीं खाते।',
        'warn_empty_account': 'खाता नाम खाली नहीं हो सकता।',
        'warn_select_row':    'पहले एक पंक्ति चुनें।',
        'err_wrong_pw':       'गलत पासवर्ड (या फ़ाइल दूषित है)।',
        'title_warning':      'चेतावनी',
        'title_error':        'त्रुटि',
        'title_info':         'जानकारी',
        'title_delete':       'हटाएं',
        'title_weak_pw':      'कमज़ोर पासवर्ड',
        'confirm_delete':     "'{account}' हटाएं?",
        'confirm_weak_pw':    '{feedback}\n\nफिर भी जारी रखें?',
        'backoff_locked':     'बहुत अधिक असफल प्रयास। {n} सेकंड प्रतीक्षा करें।',
        'backoff_waiting':    'गलत पासवर्ड — {n} सेकंड प्रतीक्षा। (प्रयास {count})',
        'backoff_wrong':      'गलत पासवर्ड। (प्रयास {count})',
        'pw_too_weak':        'पासवर्ड अनुमानित या बहुत कमज़ोर है।',
        'pw_weak_fallback':   (
            'पासवर्ड कम से कम 12 अक्षरों का होना चाहिए और इसमें '
            'बड़े/छोटे अक्षर, अंक और विशेष वर्ण होने चाहिए।\n\n'
            '(बेहतर विश्लेषण: pip3 install zxcvbn)'
        ),
        'status_bar': (
            'डबल-क्लिक करके संपादित करें  •  क्लिपबोर्ड 15 सेकंड में साफ़  •  '
            '{mins} मिनट बाद स्वत: लॉक'
        ),
    },
}

LANG_NAMES: dict[str, str] = {
    'en': 'English',
    'es': 'Español',
    'de': 'Deutsch',
    'zh': '中文',
    'ja': '日本語',
    'fr': 'Français',
    'hi': 'हिन्दी',
}

CONFIG_FILE = os.path.join(os.path.expanduser('~'), '.casa_config.json')
_lang = 'en'


def _load_lang() -> None:
    global _lang
    try:
        with open(CONFIG_FILE) as f:
            data = json.load(f)
        if data.get('lang') in TRANSLATIONS:
            _lang = data['lang']
    except Exception:
        pass


def _save_lang() -> None:
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump({'lang': _lang}, f)
    except OSError:
        pass


def t(key: str, **kw) -> str:
    s = TRANSLATIONS.get(_lang, TRANSLATIONS['en']).get(key) \
        or TRANSLATIONS['en'].get(key, key)
    return s.format(**kw) if kw else s


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
VAULT_FILE = os.path.join(os.path.expanduser('~'), '.casa_vault.dat')
VAULT_MAGIC = b'CASA'
VAULT_VERSION = 1

ARGON_TIME        = 4
ARGON_MEMORY      = 256 * 1024   # KiB = 256 MB
ARGON_PARALLELISM = 4
KEY_LEN           = 32
SALT_LEN          = 16
NONCE_LEN         = 12

CLIPBOARD_CLEAR_MS = 15_000
LOCK_TIMEOUT_MS    = 5 * 60_000
MASK               = '•' * 8


# ---------------------------------------------------------------------------
# Secure memory buffer
# ---------------------------------------------------------------------------
class SecureBuffer:
    """mlock-pinned buffer; wipe() zeros it and releases the lock."""

    _libc = None

    @classmethod
    def _get_libc(cls):
        if cls._libc is None:
            try:
                cls._libc = ctypes.CDLL(ctypes.util.find_library('c'))
            except Exception:
                pass
        return cls._libc

    def __init__(self, data: bytes):
        self._len    = len(data)
        self._locked = False
        self._buf    = ctypes.create_string_buffer(data, self._len)
        libc = self._get_libc()
        if libc:
            try:
                ret          = libc.mlock(self._buf, ctypes.c_size_t(self._len))
                self._locked = (ret == 0)
            except Exception:
                pass
        if not self._locked:
            print(
                '[WARNING] mlock failed: buffer may be written to swap. '
                'Check RLIMIT_MEMLOCK.',
                file=sys.stderr,
            )

    def get(self) -> bytes:
        if self._len == 0:
            raise ValueError('SecureBuffer has already been wiped.')
        return bytes(self._buf.raw[: self._len])

    def wipe(self) -> None:
        if self._len > 0:
            ctypes.memset(self._buf, 0, self._len)
            libc = self._get_libc()
            if libc and self._locked:
                try:
                    libc.munlock(self._buf, ctypes.c_size_t(self._len))
                except Exception:
                    pass
            self._len = 0

    def __del__(self):
        self.wipe()


# ---------------------------------------------------------------------------
# In-memory encrypted store
# ---------------------------------------------------------------------------
class EncryptedStore:
    """
    Keeps vault entries encrypted in memory with a random session key.
    Account names and usernames are plaintext (needed for display).
    Passwords are individually AES-256-GCM encrypted; decrypted only on
    copy / edit operations.
    """

    def __init__(self, entries: list):
        self._session_key   = SecureBuffer(os.urandom(KEY_LEN))
        self._metadata:      list[dict]  = []
        self._enc_passwords: list[bytes] = []
        for e in entries:
            self._append_raw(e.get('account', ''), e.get('username', ''), e.get('password', ''))

    def _append_raw(self, account: str, username: str, password: str) -> None:
        self._metadata.append({'account': account, 'username': username})
        self._enc_passwords.append(self._enc_pw(password))

    def _enc_pw(self, password: str) -> bytes:
        key   = self._session_key.get()
        nonce = os.urandom(NONCE_LEN)
        ct    = AESGCM(key).encrypt(nonce, password.encode('utf-8'), None)
        return nonce + ct

    def _dec_pw(self, blob: bytes) -> str:
        key   = self._session_key.get()
        nonce = blob[:NONCE_LEN]
        ct    = blob[NONCE_LEN:]
        return AESGCM(key).decrypt(nonce, ct, None).decode('utf-8')

    def count(self) -> int:
        return len(self._metadata)

    def get_display(self, index: int, show_password: bool) -> tuple:
        m      = self._metadata[index]
        pw_str = self._dec_pw(self._enc_passwords[index]) if show_password \
                 else (MASK if self._enc_passwords[index] else '')
        return m['account'], m['username'], pw_str

    def get_password(self, index: int) -> str:
        return self._dec_pw(self._enc_passwords[index])

    def get_full_entry(self, index: int) -> dict:
        m = self._metadata[index]
        return {'account': m['account'], 'username': m['username'],
                'password': self._dec_pw(self._enc_passwords[index])}

    def get_account_name(self, index: int) -> str:
        return self._metadata[index]['account']

    def add(self, entry: dict) -> None:
        self._append_raw(entry.get('account', ''), entry.get('username', ''),
                         entry.get('password', ''))

    def update(self, index: int, entry: dict) -> None:
        self._metadata[index]      = {'account': entry.get('account', ''),
                                      'username': entry.get('username', '')}
        self._enc_passwords[index] = self._enc_pw(entry.get('password', ''))

    def remove(self, index: int) -> None:
        self._metadata.pop(index)
        self._enc_passwords.pop(index)

    def get_entries_for_save(self) -> list:
        return [
            {'account':  self._metadata[i]['account'],
             'username': self._metadata[i]['username'],
             'password': self._dec_pw(self._enc_passwords[i])}
            for i in range(len(self._metadata))
        ]

    def wipe(self) -> None:
        self._session_key.wipe()
        self._metadata.clear()
        self._enc_passwords.clear()

    def __del__(self):
        self.wipe()


# ---------------------------------------------------------------------------
# Crypto layer
# ---------------------------------------------------------------------------
def derive_key(master_password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode('utf-8'),
        salt=salt,
        time_cost=ARGON_TIME,
        memory_cost=ARGON_MEMORY,
        parallelism=ARGON_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def encrypt_vault(entries: list, key: bytes, salt: bytes) -> bytes:
    nonce     = os.urandom(NONCE_LEN)
    raw       = json.dumps(entries, ensure_ascii=False).encode('utf-8')
    plaintext = bytearray(raw)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), None)
        return VAULT_MAGIC + bytes([VAULT_VERSION]) + salt + nonce + ciphertext
    finally:
        for i in range(len(plaintext)):
            plaintext[i] = 0


def decrypt_vault(blob: bytes, master_password: str):
    if blob[:4] == VAULT_MAGIC:
        if blob[4] != VAULT_VERSION:
            raise ValueError(f'Unsupported vault version: {blob[4]}')
        offset = 5
    else:
        offset = 0

    salt       = blob[offset: offset + SALT_LEN]
    nonce      = blob[offset + SALT_LEN: offset + SALT_LEN + NONCE_LEN]
    ciphertext = blob[offset + SALT_LEN + NONCE_LEN:]
    key        = derive_key(master_password, salt)
    raw        = bytearray(AESGCM(key).decrypt(nonce, ciphertext, None))
    try:
        entries = json.loads(raw.decode('utf-8'))
        # Migrate old Turkish field names if present
        migrated = []
        for e in entries:
            migrated.append({
                'account':  e.get('account',  e.get('hesap',     '')),
                'username': e.get('username', e.get('kullanici',  '')),
                'password': e.get('password', e.get('sifre',      '')),
            })
        return migrated, key, salt
    finally:
        for i in range(len(raw)):
            raw[i] = 0


# ---------------------------------------------------------------------------
# Password strength
# ---------------------------------------------------------------------------
def check_password_strength(password: str) -> tuple[bool, str]:
    if ZXCVBN_AVAILABLE:
        result      = _zxcvbn(password)
        score       = result['score']
        if score < 3:
            feedback    = result['feedback']
            warning     = feedback.get('warning', '')
            suggestions = feedback.get('suggestions', [])
            msg = warning if warning else t('pw_too_weak')
            if suggestions:
                msg += '\n' + '\n'.join(f'• {s}' for s in suggestions[:3])
            return False, msg
        return True, ''
    checks = [
        len(password) >= 12,
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    if sum(checks) < 4:
        return False, t('pw_weak_fallback')
    return True, ''


# ---------------------------------------------------------------------------
# Language selector widget (reusable)
# ---------------------------------------------------------------------------
def make_lang_selector(parent, on_change, side='right', padx=0):
    """Returns (frame, StringVar). on_change(lang_code) is called on selection."""
    frame   = ttk.Frame(parent)
    lv      = tk.StringVar(value=_lang)
    options = list(LANG_NAMES.keys())

    ttk.Label(frame, text=t('label_language')).pack(side='left')
    menu = ttk.OptionMenu(
        frame, lv, _lang,
        *options,
        command=lambda v: on_change(v),
    )
    # Replace display values with native language names
    menu['menu'].delete(0, 'end')
    for code in options:
        menu['menu'].add_command(
            label=LANG_NAMES[code],
            command=lambda c=code: (lv.set(c), on_change(c)),
        )
    menu.pack(side='left', padx=(4, 0))
    frame.pack(side=side, padx=padx)
    return frame, lv


# ---------------------------------------------------------------------------
# Unlock / create dialog
# ---------------------------------------------------------------------------
class UnlockDialog(tk.Toplevel):
    """Asks for master password; handles new-vault creation and brute-force back-off."""

    def __init__(self, master, vault_exists: bool):
        super().__init__(master)
        self.vault_exists  = vault_exists
        self.result        = None
        self._fail_count   = 0
        self._locked_until = 0.0

        self.resizable(False, False)
        self.configure(padx=24, pady=20)
        self.grab_set()

        self._build_ui()

    # ---- UI construction ----

    def _build_ui(self) -> None:
        for w in self.winfo_children():
            w.destroy()

        self.title(t('app_title'))

        head_text = t('unlock_prompt') if self.vault_exists else t('create_prompt')
        self._lbl_head = ttk.Label(self, text=head_text, justify='center')
        self._lbl_head.grid(row=0, column=0, columnspan=2, pady=(0, 14))

        self._lbl_pw = ttk.Label(self, text=t('label_master_pw'))
        self._lbl_pw.grid(row=1, column=0, sticky='e', pady=4)
        self.pw1 = ttk.Entry(self, show='•', width=28)
        self.pw1.grid(row=1, column=1, pady=4)
        self.pw1.focus_set()

        if not self.vault_exists:
            self._lbl_confirm = ttk.Label(self, text=t('label_confirm'))
            self._lbl_confirm.grid(row=2, column=0, sticky='e', pady=4)
            self.pw2 = ttk.Entry(self, show='•', width=28)
            self.pw2.grid(row=2, column=1, pady=4)

        self._status_var = tk.StringVar()
        ttk.Label(self, textvariable=self._status_var,
                  foreground='red', wraplength=300, justify='center').grid(
            row=3, column=0, columnspan=2, pady=4)

        # Language selector
        lang_frame = ttk.Frame(self)
        ttk.Label(lang_frame, text=t('label_language')).pack(side='left')
        self._lang_var = tk.StringVar(value=_lang)
        lang_menu = ttk.OptionMenu(lang_frame, self._lang_var, _lang)
        lang_menu['menu'].delete(0, 'end')
        for code, name in LANG_NAMES.items():
            lang_menu['menu'].add_command(
                label=name,
                command=lambda c=code: self._change_lang(c),
            )
        lang_menu.pack(side='left', padx=(4, 0))
        lang_frame.grid(row=4, column=0, columnspan=2, pady=(6, 0))

        self._btn = ttk.Button(
            self,
            text=t('btn_unlock') if self.vault_exists else t('btn_create'),
            command=self._submit,
        )
        self._btn.grid(row=5, column=0, columnspan=2, pady=(12, 0), sticky='ew')

        self.bind('<Return>', lambda e: self._submit())
        self.protocol('WM_DELETE_WINDOW', self._cancel)

    def _change_lang(self, code: str) -> None:
        global _lang
        _lang = code
        _save_lang()
        self._lang_var.set(code)
        self._rebuild_texts()

    def _rebuild_texts(self) -> None:
        self.title(t('app_title'))
        self._lbl_head.config(
            text=t('unlock_prompt') if self.vault_exists else t('create_prompt'))
        self._lbl_pw.config(text=t('label_master_pw'))
        if not self.vault_exists:
            self._lbl_confirm.config(text=t('label_confirm'))
        self._btn.config(
            text=t('btn_unlock') if self.vault_exists else t('btn_create'))

    # ---- Back-off ----

    def _backoff_seconds(self) -> float:
        return 0.0 if self._fail_count < 2 else float(min(2 ** (self._fail_count - 1), 60))

    # ---- Submit ----

    def _submit(self) -> None:
        remaining = self._locked_until - time.time()
        if remaining > 0:
            self._status_var.set(t('backoff_locked', n=f'{remaining:.0f}'))
            return

        pw = self.pw1.get()
        if not pw:
            messagebox.showwarning(t('title_warning'), t('warn_empty_pw'), parent=self)
            return

        if self.vault_exists:
            self._btn.config(state='disabled')
            self._status_var.set(t('verifying'))
            self.update()
            try:
                with open(VAULT_FILE, 'rb') as f:
                    blob = f.read()
                entries, key, salt = decrypt_vault(blob, pw)
                self.result = (entries, key, salt)
                self._btn.config(state='normal')
                self.destroy()
            except (InvalidTag, ValueError):
                self._fail_count     += 1
                delay                 = self._backoff_seconds()
                self._locked_until    = time.time() + delay
                self._btn.config(state='normal')
                self._status_var.set(
                    t('backoff_waiting', n=f'{delay:.0f}', count=self._fail_count)
                    if delay > 0 else
                    t('backoff_wrong', count=self._fail_count)
                )
                self.pw1.delete(0, tk.END)
                self.pw1.focus_set()
        else:
            if pw != self.pw2.get():
                messagebox.showwarning(t('title_warning'), t('warn_no_match'), parent=self)
                return
            ok, feedback = check_password_strength(pw)
            if not ok:
                if not messagebox.askyesno(
                        t('title_weak_pw'),
                        t('confirm_weak_pw', feedback=feedback),
                        parent=self):
                    return
            self._btn.config(state='disabled')
            self._status_var.set(t('deriving_key'))
            self.update()
            salt       = os.urandom(SALT_LEN)
            key        = derive_key(pw, salt)
            self.result = ([], key, salt)
            self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()


# ---------------------------------------------------------------------------
# Add / edit entry dialog
# ---------------------------------------------------------------------------
class EntryDialog(tk.Toplevel):
    def __init__(self, master, title: str, entry: dict | None = None):
        super().__init__(master)
        self.result = None
        self.title(title)
        self.resizable(False, False)
        self.configure(padx=24, pady=20)
        self.grab_set()

        entry = entry or {'account': '', 'username': '', 'password': ''}

        ttk.Label(self, text=t('label_account')).grid(row=0, column=0, sticky='e', pady=4)
        self.e_account = ttk.Entry(self, width=32)
        self.e_account.grid(row=0, column=1, pady=4)
        self.e_account.insert(0, entry['account'])

        ttk.Label(self, text=t('label_username')).grid(row=1, column=0, sticky='e', pady=4)
        self.e_username = ttk.Entry(self, width=32)
        self.e_username.grid(row=1, column=1, pady=4)
        self.e_username.insert(0, entry['username'])

        ttk.Label(self, text=t('label_password')).grid(row=2, column=0, sticky='e', pady=4)
        self.e_password = ttk.Entry(self, width=32, show='•')
        self.e_password.grid(row=2, column=1, pady=4)
        self.e_password.insert(0, entry['password'])

        self._show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text=t('chk_show_password'),
                        variable=self._show_var,
                        command=self._toggle).grid(row=3, column=1, sticky='w')

        ttk.Button(self, text=t('btn_save'), command=self._submit).grid(
            row=4, column=0, columnspan=2, pady=(14, 0), sticky='ew')

        self.e_account.focus_set()
        self.bind('<Return>', lambda e: self._submit())

    def _toggle(self) -> None:
        self.e_password.config(show='' if self._show_var.get() else '•')

    def _submit(self) -> None:
        account = self.e_account.get().strip()
        if not account:
            messagebox.showwarning(t('title_warning'), t('warn_empty_account'), parent=self)
            return
        self.result = {
            'account':  account,
            'username': self.e_username.get().strip(),
            'password': self.e_password.get(),
        }
        self.destroy()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class VaultApp:
    def __init__(self, root: tk.Tk, entries: list, key: bytes, salt: bytes):
        self.root         = root
        self._secure_key  = SecureBuffer(key)
        self.salt         = salt
        self.store        = EncryptedStore(entries)
        self._show_pw     = False
        self._clip_token  = None
        self._lock_token  = None

        root.geometry('720x440')
        root.minsize(580, 340)
        root.protocol('WM_DELETE_WINDOW', self._on_close)

        self._build_ui()
        self._setup_auto_lock()
        self.refresh()

    # ---- UI construction ----

    def _build_ui(self) -> None:
        # Toolbar
        bar = ttk.Frame(self.root, padding=(10, 8))
        bar.pack(fill='x')

        self._btn_add    = ttk.Button(bar, text=t('btn_add'),    command=self.add_entry)
        self._btn_edit   = ttk.Button(bar, text=t('btn_edit'),   command=self.edit_entry)
        self._btn_delete = ttk.Button(bar, text=t('btn_delete'), command=self.delete_entry)
        self._btn_copy   = ttk.Button(bar, text=t('btn_copy_pw'), command=self.copy_password)
        self._btn_lock   = ttk.Button(bar, text=t('btn_lock'),   command=self._lock)
        self._btn_add.pack(side='left')
        self._btn_edit.pack(side='left', padx=6)
        self._btn_delete.pack(side='left')
        self._btn_copy.pack(side='left', padx=6)
        self._btn_lock.pack(side='left', padx=6)

        # Language selector (right side)
        self._lang_var = tk.StringVar(value=_lang)
        lang_frame = ttk.Frame(bar)
        ttk.Label(lang_frame, text=t('label_language')).pack(side='left')
        lang_menu = ttk.OptionMenu(lang_frame, self._lang_var, _lang)
        lang_menu['menu'].delete(0, 'end')
        for code, name in LANG_NAMES.items():
            lang_menu['menu'].add_command(
                label=name,
                command=lambda c=code: self._change_lang(c),
            )
        lang_menu.pack(side='left', padx=(4, 0))
        lang_frame.pack(side='right', padx=(0, 6))

        # Show-passwords checkbox (right side)
        self._show_var = tk.BooleanVar(value=False)
        self._chk_show = ttk.Checkbutton(bar, text=t('chk_show_passwords'),
                                         variable=self._show_var,
                                         command=self._toggle_show)
        self._chk_show.pack(side='right', padx=6)

        # Table
        cols = ('account', 'username', 'password')
        self.tree = ttk.Treeview(self.root, columns=cols,
                                 show='headings', selectmode='browse')
        self.tree.heading('account',  text=t('col_account'))
        self.tree.heading('username', text=t('col_username'))
        self.tree.heading('password', text=t('col_password'))
        self.tree.column('account',  width=200, anchor='w')
        self.tree.column('username', width=240, anchor='w')
        self.tree.column('password', width=220, anchor='w')
        self.tree.pack(fill='both', expand=True, padx=10, pady=(0, 6))
        self.tree.bind('<Double-1>', lambda e: self.edit_entry())

        self._status_var = tk.StringVar()
        ttk.Label(self.root, textvariable=self._status_var,
                  foreground='#888').pack(pady=(0, 8))

    def _apply_lang(self) -> None:
        self.root.title(t('app_title'))
        self._btn_add.config(text=t('btn_add'))
        self._btn_edit.config(text=t('btn_edit'))
        self._btn_delete.config(text=t('btn_delete'))
        self._btn_copy.config(text=t('btn_copy_pw'))
        self._btn_lock.config(text=t('btn_lock'))
        self._chk_show.config(text=t('chk_show_passwords'))
        self.tree.heading('account',  text=t('col_account'))
        self.tree.heading('username', text=t('col_username'))
        self.tree.heading('password', text=t('col_password'))
        self._reset_lock_timer()
        self.refresh()

    def _change_lang(self, code: str) -> None:
        global _lang
        _lang = code
        _save_lang()
        self._lang_var.set(code)
        self._apply_lang()

    # ---- Auto-lock ----

    def _setup_auto_lock(self) -> None:
        self._reset_lock_timer()
        self.root.bind_all('<KeyPress>',    self._on_activity, add='+')
        self.root.bind_all('<ButtonPress>', self._on_activity, add='+')
        self.root.bind_all('<Motion>',      self._on_activity, add='+')

    def _on_activity(self, *_) -> None:
        self._reset_lock_timer()

    def _reset_lock_timer(self) -> None:
        if self._lock_token:
            self.root.after_cancel(self._lock_token)
        self._lock_token = self.root.after(LOCK_TIMEOUT_MS, self._lock)
        mins = LOCK_TIMEOUT_MS // 60_000
        self._status_var.set(t('status_bar', mins=mins))

    def _lock(self) -> None:
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
        self._secure_key.wipe()
        self._secure_key = SecureBuffer(key)
        self.salt        = salt
        self.store       = EncryptedStore(entries)
        self.root.deiconify()
        self._apply_lang()
        self._reset_lock_timer()
        self.refresh()

    def _on_close(self) -> None:
        self.store.wipe()
        self._secure_key.wipe()
        self.root.destroy()

    # ---- Table ----

    def refresh(self) -> None:
        sel = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for i in range(self.store.count()):
            account, username, pw = self.store.get_display(i, self._show_pw)
            self.tree.insert('', 'end', iid=str(i),
                             values=(account, username, pw))
        if sel and sel[0] in self.tree.get_children():
            self.tree.selection_set(sel)

    def _toggle_show(self) -> None:
        self._show_pw = self._show_var.get()
        self.refresh()

    def _selected_index(self) -> int | None:
        sel = self.tree.selection()
        return int(sel[0]) if sel else None

    # ---- CRUD ----

    def add_entry(self) -> None:
        dlg = EntryDialog(self.root, t('dlg_new_entry'))
        self.root.wait_window(dlg)
        if dlg.result:
            self.store.add(dlg.result)
            self.save()
            self.refresh()

    def edit_entry(self) -> None:
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo(t('title_info'), t('warn_select_row'))
            return
        dlg = EntryDialog(self.root, t('dlg_edit_entry'),
                          self.store.get_full_entry(idx))
        self.root.wait_window(dlg)
        if dlg.result:
            self.store.update(idx, dlg.result)
            self.save()
            self.refresh()

    def delete_entry(self) -> None:
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo(t('title_info'), t('warn_select_row'))
            return
        if messagebox.askyesno(
                t('title_delete'),
                t('confirm_delete', account=self.store.get_account_name(idx))):
            self.store.remove(idx)
            self.save()
            self.refresh()

    # ---- Clipboard ----

    def copy_password(self) -> None:
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo(t('title_info'), t('warn_select_row'))
            return
        pw = self.store.get_password(idx)
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        if self._clip_token:
            self.root.after_cancel(self._clip_token)
        self._clip_token = self.root.after(
            CLIPBOARD_CLEAR_MS, lambda: self._clear_clip(pw))

    def _clear_clip(self, expected: str) -> None:
        try:
            if self.root.clipboard_get() == expected:
                self.root.clipboard_clear()
                self.root.clipboard_append('')
        except tk.TclError:
            pass
        self._clip_token = None

    # ---- Save ----

    def save(self) -> None:
        entries = self.store.get_entries_for_save()
        key     = self._secure_key.get()
        blob    = encrypt_vault(entries, key, self.salt)
        tmp     = VAULT_FILE + '.tmp'
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as f:
            f.write(blob)
        os.replace(tmp, VAULT_FILE)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    _load_lang()

    root = tk.Tk()
    root.withdraw()

    vault_exists = os.path.exists(VAULT_FILE)
    dlg = UnlockDialog(root, vault_exists)
    root.wait_window(dlg)

    if dlg.result is None:
        root.destroy()
        return

    entries, key, salt = dlg.result
    root.title(t('app_title'))
    root.deiconify()
    VaultApp(root, entries, key, salt)
    root.mainloop()


if __name__ == '__main__':
    main()
