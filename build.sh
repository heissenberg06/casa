#!/bin/bash
# Casa.app build scripti
# Kullanım: bash build.sh

set -e

DIST_DIR="dist"
APP_NAME="Casa.app"
ZIP_NAME="Casa-macOS.zip"

echo "========================================"
echo "  Casa Password Vault — macOS App Build"
echo "========================================"
echo ""

# PyInstaller kontrolü
if ! command -v pyinstaller &>/dev/null; then
    echo "PyInstaller bulunamadı. Kuruluyor..."
    pip3 install pyinstaller --break-system-packages
fi

# Eski build'i temizle
echo "Temizleniyor..."
rm -rf build dist __pycache__ *.pyc

# Opsiyonel: icon.icns varsa bilgi ver
if [ -f "icon.icns" ]; then
    echo "Özel ikon bulundu: icon.icns"
else
    echo "icon.icns bulunamadı — varsayılan ikon kullanılacak."
fi

echo ""
echo "Build başlıyor (ilk seferinde 1-2 dk sürebilir)..."
echo ""

# Build
pyinstaller casa.spec --noconfirm

echo ""
echo "========================================"
echo "  Build tamamlandı!"
echo "========================================"
echo ""
echo "Uygulama: dist/Casa.app"
echo ""

# Dağıtım için zip oluştur
cd dist
zip -r --quiet "../$ZIP_NAME" "$APP_NAME"
cd ..

echo "Dağıtım paketi: $ZIP_NAME"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  DAĞITIM NOTU"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Uygulama imzasız olduğundan diğer kullanıcılar"
echo "ilk açılışta şu adımı uygulamalı:"
echo ""
echo "  1. Casa.app üzerine sağ tık → Aç"
echo "  2. Açılan uyarı penceresinde tekrar 'Aç' tıkla"
echo ""
echo "Sonraki açılışlarda normal çift tıkla çalışır."
echo ""
