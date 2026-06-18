#!/bin/bash
# Casa.app build script
# Usage: bash build.sh

set -e

APP_NAME="Casa.app"
ZIP_NAME="Casa-macOS.zip"

echo "========================================"
echo "  Casa Password Vault — macOS App Build"
echo "========================================"
echo ""

# Check for PyInstaller
if ! command -v pyinstaller &>/dev/null; then
    echo "PyInstaller not found. Installing..."
    pip3 install pyinstaller --break-system-packages
fi

# Clean previous build
echo "Cleaning previous build..."
rm -rf build dist __pycache__ *.pyc

# Optional custom icon
if [ -f "icon.icns" ]; then
    echo "Custom icon found: icon.icns"
else
    echo "icon.icns not found — default icon will be used."
fi

echo ""
echo "Building (may take 1-2 min on first run)..."
echo ""

pyinstaller casa.spec --noconfirm

echo ""
echo "========================================"
echo "  Build complete!"
echo "========================================"
echo ""
echo "App: dist/Casa.app"
echo ""

# Create distribution zip
cd dist
zip -r --quiet "../$ZIP_NAME" "$APP_NAME"
cd ..

echo "Distribution package: $ZIP_NAME"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  DISTRIBUTION NOTE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "The app is unsigned. On first launch, other"
echo "users must bypass Gatekeeper:"
echo ""
echo "  1. Right-click Casa.app → Open"
echo "  2. Click 'Open' in the warning dialog"
echo ""
echo "Subsequent launches work with a normal double-click."
echo ""
