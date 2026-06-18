# -*- mode: python ; coding: utf-8 -*-
import os

icon_file = 'icon.icns' if os.path.exists('icon.icns') else None

a = Analysis(
    ['casa.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # argon2
        'argon2',
        'argon2.low_level',
        'argon2._utils',
        'argon2.exceptions',
        # cryptography
        'cryptography',
        'cryptography.hazmat',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.backends.openssl',
        'cryptography.exceptions',
        # zxcvbn
        'zxcvbn',
        'zxcvbn.matching',
        'zxcvbn.scoring',
        'zxcvbn.time_estimates',
        'zxcvbn.feedback',
        'zxcvbn.adjacency_graphs',
        'zxcvbn.frequency_lists',
        # tkinter
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        '_tkinter',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'PIL', 'scipy', 'pandas'],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Casa',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,        # terminal penceresi açılmaz
    argv_emulation=False,
    target_arch=None,     # mevcut mimari (arm64 veya x86_64)
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name='Casa',
)

app = BUNDLE(
    coll,
    name='Casa.app',
    icon=icon_file,
    bundle_identifier='com.casa.passwordvault',
    info_plist={
        'CFBundleName': 'Casa',
        'CFBundleDisplayName': 'Casa Password Vault',
        'CFBundleVersion': '1.0.0',
        'CFBundleShortVersionString': '1.0',
        'CFBundleExecutable': 'Casa',
        'NSHighResolutionCapable': True,
        'NSHumanReadableDescription': 'Offline password vault',
        'NSRequiresAquaSystemAppearance': False,
        'LSMinimumSystemVersion': '12.0',
        # Gerekli izinler yok — tamamen offline, dosya sistemi dışına erişmez
    },
)
