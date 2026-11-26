#!/bin/bash
# ============================================================================
# vmp_batch.sh — VMProtect 3.9.4 TOPLU DERLEME MOTORU (sandbox/wine)
# ============================================================================
#  Her varyant için:
#    1) .vmp projesi yaz (Options bitleri + MovePlayer CompilationType + çıktı adı)
#    2) wine VMProtect.exe MP_batch.vmp  (Xvfb :95 üzerinde)
#    3) UQ TUL: uqt_agent --pid N  →  {"cmd":"xkey","keysym":"F9"}
#       (XTEST giriş enjeksiyonu = aracın kendi komutu!)
#    4) çıktı dosyasının oturmasını bekle → kaydet
#    5) örneği kapat, sonraki varyant
#  SS/OCR YOK — pencere odaklama + XTEST gerçek olay + bellek taraması.
#
#  Kullanım: vmp_batch.sh <varyant-listesi-dosyası|varyant1,varyant2,...>
#    varyant adları: MP IP RP AD ML ALL MPU MPM MPV MPUI MPUALL
#    (kısaltmalar — aşağıdaki tablo)
# ============================================================================
set -u
W=/home/z/my-project/vmprotect/wine_root
export WINEPREFIX=/home/z/my-project/vmprotect/wineprefix
export PATH="$W/usr/lib/wine:$PATH"
export LD_PRELOAD=$W/wineshim.so
export WINEDLLPATH="$W/usr/lib/x86_64-linux-gnu/wine"
VMPDIR="/home/z/my-project/vmprotect/allver/Allver_Collection/VMProtect Ultimate 3.9.4/VMProtect Ultimate 3.94"
AGENT=/home/z/my-project/UniversalMVPUIAlgorithm_QT/uqt_agent
CLI=/home/z/my-project/UniversalMVPUIAlgorithm_QT/umvpqt_cli
OUTDIR=/home/z/my-project/vmprotect/compiled
mkdir -p $OUTDIR
cp /home/z/my-project/upload/Test_64.exe "$VMPDIR/Test_64.exe" 2>/dev/null

# ---- varyant tablosu: ad | global Options (hex) | MovePlayer CT ----
# CT: "" = MovePlayer YOK; 0=Virtualization, 1=Mutation, 2=Ultra
# Options bitleri (core.h ProjectOption):
#   0x0008 CryptValues | 0x0040 RunnerCRC | 0x0080 EncryptRegs | 0x0100 Pack
#   0x0200 ImportProtection | 0x0400 CheckDebugger | 0x0800 CheckVirtualMachine
#   0x1000 MemoryProtection | 0x8000 StripFixups | 0x10000 ResourceProtection
#   0x20000 CheckKernelDebugger | 0x40000 StripDebugInfo
ALL_OPTS=$((0x8 + 0x40 + 0x80 + 0x100 + 0x200 + 0x1000 + 0x10000 + 0x40000))
variants() {
  case "$1" in
    MP)     echo "Test_64_MemoryProtection|0x1000|";;
    IP)     echo "Test_64_ImportProtection|0x200|";;
    RP)     echo "Test_64_ResourceProtection|0x10000|";;
    AD)     echo "Test_64_Antidebug|0x20400|";;
    ML)     echo "Test_64_MemoryLimitation|0x800|";;
    ALL)    echo "Test_64_ALL|$(printf '0x%x' $ALL_OPTS)|";;
    MPV)    echo "Test_64_MovePlayer_VIRTUALIZATION|0x0|0";;
    MPM)    echo "Test_64_MovePlayer_MUTATION|0x0|1";;
    MPU)    echo "Test_64_MovePlayer_ULTRA|0x0|2";;
    MPUI)   echo "Test_64_MovePlayer_ULTRA_ImportProtection|0x200|2";;
    MPUALL) echo "Test_64_MovePlayer_ULTRA_ALL|$(printf '0x%x' $ALL_OPTS)|2";;
    *)      echo "";;
  esac
}

compile_one() {
    local NAME OPTS CT
    NAME=$1; OPTS=$2; CT=$3
    echo "--- VARYANT: $NAME (Options=$OPTS CT=${CT:-yok}) ---"
    local PROC=""
    if [ -n "$CT" ]; then
        PROC="            <Procedure MapAddress=\"MovePlayer\" CompilationType=\"$CT\" Options=\"0\" />"
    fi
    cat > "$VMPDIR/MP_batch.vmp" << EOF
<?xml version="1.0" encoding="UTF-8" ?>
<Document>
    <Protection InputFileName="Test_64.exe" Options="$OPTS" RunParameters="" OutputFileName="$NAME.vmp.exe">
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
    rm -f "$VMPDIR/$NAME.vmp.exe"

    Xvfb :95 -screen 0 1600x1000x24 -nolisten tcp >/dev/null 2>&1 &
    local XVFB=$!
    sleep 2
    ( cd "$VMPDIR" && DISPLAY=:95 "$W/usr/lib/wine/wine64" VMProtect.exe MP_batch.vmp > /tmp/vmp_batch_wine.log 2>&1 & )
    local VMPID=""
    for i in $(seq 1 30); do sleep 2; VMPID=$(pgrep -f "VMProtect.exe" | head -1); [ -n "$VMPID" ] && break; done
    [ -z "$VMPID" ] && { echo "  HATA: süreç açılmadı"; kill $XVFB 2>/dev/null; return 1; }

    # yerleşme: pencere açılıp Qt döngüsü otursun (75sn — kanıtlanmış aralık)
    sleep 75
    kill -0 $VMPID 2>/dev/null || { echo "  HATA: süreç öldü"; kill $XVFB 2>/dev/null; return 1; }

    # ---- ARACIN KENDİ KOMUTUYLA F9 (XTEST enjeksiyonu) ----
    echo '{"cmd":"attach","pid":'$VMPID'}
{"cmd":"xkey","keysym":"F9"}
{"cmd":"quit"}' | DISPLAY=:95 timeout 120 $AGENT --pid $VMPID 2>/dev/null | grep -E '"xkey"' | head -1

    # ---- çıktıyı bekle (maks 90sn) ----
    local DONE=""
    for i in $(seq 1 9); do
        sleep 10
        if [ -f "$VMPDIR/$NAME.vmp.exe" ]; then
            local SZ SZ2
            SZ=$(stat -c%s "$VMPDIR/$NAME.vmp.exe" 2>/dev/null)
            sleep 4
            SZ2=$(stat -c%s "$VMPDIR/$NAME.vmp.exe" 2>/dev/null)
            if [ "$SZ" = "$SZ2" ] && [ "$SZ" -gt 1000 ]; then DONE=1; break; fi
        fi
        kill -0 $VMPID 2>/dev/null || break
    done
    if [ -n "$DONE" ]; then
        cp "$VMPDIR/$NAME.vmp.exe" "$OUTDIR/"
        echo "  ÜRETTİ: $OUTDIR/$NAME.vmp.exe ($(stat -c%s "$OUTDIR/$NAME.vmp.exe") bayt)"
    else
        echo "  BAŞARISIZ: $NAME"
    fi
    pkill -f "VMProtect.exe" 2>/dev/null; sleep 2
    kill $XVFB 2>/dev/null
    return 0
}

# ---- ana akış ----
LIST=${1:-MP,IP,RP,AD,ML,ALL,MPV,MPM,MPU,MPUI,MPUALL}
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
