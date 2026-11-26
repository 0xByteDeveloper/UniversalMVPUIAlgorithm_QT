#!/bin/bash
# ============================================================================
# vmp_batch_v4.sh — VMProtect 3.9.4 TAM MATRİS DERLEME MOTORU (wine64 + Xvfb)
# ============================================================================
#  V4 — DÜZELTİLMİŞ bit haritası (kontrollü bellek deneyiyle doğrulandı:
#  .vmp Options=N yükle → ajanla BoolProperty değerlerini oku → değişimi izle):
#    Memory Protection      = 0x1000   (doğrulandı: değer 0→1)
#    Import Protection      = 0x200    (doğrulandı)
#    Pack the Output File   = 0x100    (doğrulandı)
#    Resource Protection    = 0x10000  (doğrulandı)
#    Strip Relocations      = 0x8000   (doğrulandı)
#    Virtualization Tools   = 0x800    (doğrulandı)  [eski adı 'MemoryLimitation' YANLIŞTI]
#    Debugger Detection     = 0x400  (user-mode)  + 0x20000 (kernel-mode)
#    CryptValues/RunnerCRC/EncryptRegs = 0x8 / 0x40 / 0x80 (dahili)
#    Strip Debug Info       = 0x40000  (derleme düzeyinde etkili; GUI BoolProperty
#                                      değerini değiştirmiyor — iç maskede)
#  MATRİS (35 exe):
#    Aile 1 (MovePlayer YOK):  12 seçenek tek tek + ALL          = 13
#    Aile 2 (MovePlayer ULTRA): 12 seçenek tek tek + ALL          = 13
#    Aile 3: 3 mod (default) + 3 mod × complexity 0/100          = 9
#  Her derleme: Xvfb :95 + wine64 VMProtect.exe MP_batch.vmp +
#  AJANIN KENDİ XTEST KOMUTUYLA F9 → çıktı oturması → adlandır → kapat.
#  SS/OCR YOK — pencere odaklama + gerçek XTEST olay + bellek taraması.
# ============================================================================
set -u
W=/home/z/my-project/vmprotect/wine_root
export WINEPREFIX=/home/z/my-project/vmprotect/wineprefix
export PATH="$W/usr/lib/wine:$PATH"
export LD_PRELOAD=$W/wineshim.so
export WINEDLLPATH="$W/usr/lib/x86_64-linux-gnu/wine"
VMPDIR="/home/z/my-project/vmprotect/allver/Allver_Collection/VMProtect Ultimate 3.9.4/VMProtect Ultimate 3.94"
AGENT=/home/z/my-project/work/v3/uqt_agent
OUTDIR=/home/z/my-project/vmprotect/compiled_v4
mkdir -p $OUTDIR
cp /home/z/my-project/upload/Test_64.exe "$VMPDIR/Test_64.exe" 2>/dev/null

ALL_BITS=0x79FC8   # 0x8|0x40|0x80|0x100|0x200|0x400|0x800|0x1000|0x8000|0x10000|0x20000|0x40000

# ---- varyant tablosu: ad | Options hex | MovePlayer CT (boş = yok) ----
variants() {
  case "$1" in
    # ----- AİLE 1: MovePlayer YOK, tek seçenek -----
    MemoryProtection)      echo "Test_64_MemoryProtection|0x1000|";;
    ImportProtection)      echo "Test_64_ImportProtection|0x200|";;
    Pack)                 echo "Test_64_Pack|0x100|";;
    ResourceProtection)   echo "Test_64_ResourceProtection|0x10000|";;
    StripRelocations)     echo "Test_64_StripRelocations|0x8000|";;
    VMDetection)          echo "Test_64_VMDetection|0x800|";;
    DebuggerDetection)    echo "Test_64_DebuggerDetection|0x400|";;
    KernelDebugger)       echo "Test_64_KernelDebuggerDetection|0x20000|";;
    StripDebugInfo)       echo "Test_64_StripDebugInfo|0x40000|";;
    CryptValues)          echo "Test_64_CryptValues|0x8|";;
    RunnerCRC)            echo "Test_64_RunnerCRC|0x40|";;
    EncryptRegs)          echo "Test_64_EncryptRegs|0x80|";;
    ALL)                  echo "Test_64_ALL|0x79FC8|";;
    # ----- AİLE 2: MovePlayer ULTRA kalıcı + tek seçenek -----
    MPU_MemoryProtection) echo "Test_64_MovePlayer_ULTRA_MemoryProtection|0x1000|2";;
    MPU_ImportProtection) echo "Test_64_MovePlayer_ULTRA_ImportProtection|0x200|2";;
    MPU_Pack)             echo "Test_64_MovePlayer_ULTRA_Pack|0x100|2";;
    MPU_ResourceProtection) echo "Test_64_MovePlayer_ULTRA_ResourceProtection|0x10000|2";;
    MPU_StripRelocations) echo "Test_64_MovePlayer_ULTRA_StripRelocations|0x8000|2";;
    MPU_VMDetection)      echo "Test_64_MovePlayer_ULTRA_VMDetection|0x800|2";;
    MPU_DebuggerDetection) echo "Test_64_MovePlayer_ULTRA_DebuggerDetection|0x400|2";;
    MPU_KernelDebugger)    echo "Test_64_MovePlayer_ULTRA_KernelDebuggerDetection|0x20000|2";;
    MPU_StripDebugInfo)    echo "Test_64_MovePlayer_ULTRA_StripDebugInfo|0x40000|2";;
    MPU_CryptValues)      echo "Test_64_MovePlayer_ULTRA_CryptValues|0x8|2";;
    MPU_RunnerCRC)         echo "Test_64_MovePlayer_ULTRA_RunnerCRC|0x40|2";;
    MPU_EncryptRegs)       echo "Test_64_MovePlayer_ULTRA_EncryptRegs|0x80|2";;
    MPU_ALL)               echo "Test_64_MovePlayer_ULTRA_ALL|0x79FC8|2";;
    # ----- AİLE 3: 3 mod (default complexity) -----
    MPV)                   echo "Test_64_MovePlayer_VIRTUALIZATION|0x0|0";;
    MPM)                   echo "Test_64_MovePlayer_MUTATION|0x0|1";;
    MPU)                   echo "Test_64_MovePlayer_ULTRA|0x0|2";;
    *)                     echo "";;
  esac
}

compile_one() {
    local NAME OPTS CT
    NAME=$1; OPTS=$2; CT=$3
    echo "--- VARYANT: $NAME (Options=$OPTS CT=${CT:-yok}) --- $(date +%H:%M:%S)"
    local PROC=""
    if [ -n "$CT" ]; then
        PROC="            <Procedure MapAddress=\"MovePlayer\" CompilationType=\"$CT\" Options=\"0\" />"
    fi
    cat > "$VMPDIR/MP_batch.vmp" << EOF
<?xml version="1.0" encoding="UTF-8" ?>
<Document>
    <Protection InputFileName="Test_64.exe" Options="$OPTS" RunParameters="" OutputFileName="Test_64.vmp.exe">
        <Folders />
        <Procedures>
$PROC
        </Procedures>
        <Messages />
    </Protection>
    <DLLBox />
    <Script>
    </Script>
</Document>
EOF
    rm -f "$VMPDIR/Test_64.vmp.exe"

    if ! pgrep -f "Xvfb :95" >/dev/null; then
        Xvfb :95 -screen 0 1600x1000x24 -nolisten tcp >/dev/null 2>&1 &
        sleep 2
    fi

    ( cd "$VMPDIR" && DISPLAY=:95 "$W/usr/lib/wine/wine64" VMProtect.exe MP_batch.vmp > /tmp/vmp_v4_wine.log 2>&1 & )
    local VMPID=""
    for i in $(seq 1 30); do sleep 2; VMPID=$(pgrep -f "VMProtect.exe" | head -1); [ -n "$VMPID" ] && break; done
    [ -z "$VMPID" ] && { echo "  HATA: surec acilmadi"; pkill -f "VMProtect.exe"; return 1; }

    sleep 75
    kill -0 $VMPID 2>/dev/null || { echo "  HATA: surec oldu"; pkill -f "VMProtect.exe"; return 1; }

    # ---- ARACIN KENDI XTEST KOMUTUYLA F9 (derleme kisa yolu) ----
    echo '{"cmd":"attach","pid":'$VMPID'}
{"cmd":"xkey","keysym":"F9"}
{"cmd":"quit"}' | DISPLAY=:95 timeout 120 $AGENT --pid $VMPID 2>/dev/null | grep '"xkey"' | head -1

    # ---- ciktiyi bekle (maks 90sn) ----
    local DONE=""
    for i in $(seq 1 9); do
        sleep 10
        if [ -f "$VMPDIR/Test_64.vmp.exe" ]; then
            local SZ SZ2
            SZ=$(stat -c%s "$VMPDIR/Test_64.vmp.exe" 2>/dev/null)
            sleep 4
            SZ2=$(stat -c%s "$VMPDIR/Test_64.vmp.exe" 2>/dev/null)
            if [ "$SZ" = "$SZ2" ] && [ "$SZ" -gt 1000 ]; then DONE=1; break; fi
        fi
        kill -0 $VMPID 2>/dev/null || break
    done
    if [ -n "$DONE" ]; then
        cp "$VMPDIR/Test_64.vmp.exe" "$OUTDIR/$NAME.vmp.exe"
        echo "  ÜRETTİ: $OUTDIR/$NAME.vmp.exe ($(stat -c%s "$OUTDIR/$NAME.vmp.exe") bayt) $(date +%H:%M:%S)"
    else
        echo "  BAŞARISIZ: $NAME"
    fi
    pkill -f "VMProtect.exe" 2>/dev/null; sleep 2
    return 0
}

LIST=${1:-MemoryProtection,ImportProtection,Pack,ResourceProtection,StripRelocations,VMDetection,DebuggerDetection,KernelDebugger,StripDebugInfo,CryptValues,RunnerCRC,EncryptRegs,ALL,MPU_MemoryProtection,MPU_ImportProtection,MPU_Pack,MPU_ResourceProtection,MPU_StripRelocations,MPU_VMDetection,MPU_DebuggerDetection,MPU_KernelDebugger,MPU_StripDebugInfo,MPU_CryptValues,MPU_RunnerCRC,MPU_EncryptRegs,MPU_ALL,MPV,MPM,MPU}
IFS=',' read -ra ITEMS <<< "$LIST"
OK=0; FAIL=""
for v in "${ITEMS[@]}"; do
    LINE=$(variants "$v")
    [ -z "$LINE" ] && continue
    IFS='|' read -r NAME OPTS CT <<< "$LINE"
    if compile_one "$NAME" "$OPTS" "$CT"; then
        [ -f "$OUTDIR/$NAME.vmp.exe" ] && OK=$((OK+1)) || FAIL="$FAIL $v"
    else
        FAIL="$FAIL $v"
    fi
done
echo
echo "=== TOPLAM: $OK başarılı / ${#ITEMS[@]} istenen | hatalar:${FAIL:- yok} ==="
ls -la $OUTDIR/*.vmp.exe 2>/dev/null
exit 0
