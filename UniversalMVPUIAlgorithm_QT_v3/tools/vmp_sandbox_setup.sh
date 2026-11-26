#!/bin/bash
# ============================================================================
# vmp_sandbox_setup.sh — Rootless Wine + Xvfb kurulumu (V3.2 kanıt ortamı)
# ============================================================================
#  Bu ortam, gerçek VMProtect 3.9.4'ün sandbox/HEADLESS Linux'ta koşmasını ve
#  UniversalMVPUIAlgorithm_QT'nın ona bağlanmasını sağlar. Root/sudo GEREKMEZ.
#  KANIT: 4171 QObject / 391 widget / 11/11 gerçek .vmp.exe üretimi.
#  Adımlar docs/VMPROTECT_PROFILE.md §4'te ayrıntılı anlatılır.
# ============================================================================
set -eu
ROOT=${1:-/home/z/my-project/vmprotect}
mkdir -p "$ROOT/wine_pkgs" "$ROOT/wine_root"

echo "[1/6] Wine 10.0 paketleri (rootless apt-get download)..."
cd "$ROOT/wine_pkgs"
apt-get download wine64 libwine wine libxtst6

echo "[2/6] Kullanıcı alanına açılıyor..."
for f in *.deb; do dpkg -x "$f" "$ROOT/wine_root/"; done

echo "[3/6] wineserver yönlendirme (mutlak yol düzeltmesi)..."
cat > "$ROOT/wine_root/usr/lib/wine/wineserver" << EOF
#!/bin/sh -e
exec "$ROOT/wine_root/usr/lib/wine/wineserver64" -p0 "\$@"
EOF
chmod +x "$ROOT/wine_root/usr/lib/wine/wineserver"

echo "[4/6] zlib1.dll (Debian kalitalı user32.dll PE importu)..."
# MSYS2 ucrt64 zlib → PE32+ zlib1.dll
if [ ! -f "$ROOT/zlib1.dll" ]; then
    curl -sL -o "$ROOT/zlib_pkg.tar.zst" \
      "https://repo.msys2.org/mingw/ucrt64/mingw-w64-ucrt-x86_64-zlib-1.3.1-1-any.pkg.tar.zst"
    python3 -c "
import zstandard, tarfile, io
raw = zstandard.ZstdDecompressor().stream_reader(open('$ROOT/zlib_pkg.tar.zst','rb')).read()
t = tarfile.open(fileobj=io.BytesIO(raw))
for m in t.getmembers():
    if 'zlib1.dll' in m.name:
        open('$ROOT/zlib1.dll','wb').write(t.extractfile(m).read()); break
"
fi
cp "$ROOT/zlib1.dll" "$ROOT/wine_root/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/"

echo "[5/6] LD_PRELOAD yol-shim'i (open/stat/execve /usr/* → wine_root)..."
# wineshim.c: /usr/share/wine, /usr/lib/wine, /usr/lib/x86_64-linux-gnu/wine
# mutlak yollarını kullanıcı alanına yeniden yönlendirir (wineserver nls +
# builtin DLL arama yolları + wineserver betiği). Kaynak: tools/wineshim.c
if [ -f "$(dirname "$0")/wineshim.c" ]; then
    gcc -shared -fPIC -O2 -o "$ROOT/wine_root/wineshim.so" \
        "$(dirname "$0")/wineshim.c" -ldl
else
    echo "  (!) tools/wineshim.c bulunamadı — elle derleyin"
fi

echo "[6/6] Ortam değişkenleri (her koşuda export edin):"
cat << EOF
export WINEPREFIX=$ROOT/wineprefix
export PATH="$ROOT/wine_root/usr/lib/wine:\$PATH"
export LD_PRELOAD=$ROOT/wine_root/wineshim.so
export WINEDLLPATH=$ROOT/wine_root/usr/lib/x86_64-linux-gnu/wine
EOF

echo
echo "=== İlk kurulum: ==="
Xvfb :95 -screen 0 1600x1000x24 & sleep 2
DISPLAY=:95 "$ROOT/wine_root/usr/lib/wine/wine64" wineboot --init
echo "KURULUM TAMAM — docs/VMPROTECT_PROFILE.md §4'teki koşu adımlarını izleyin."
