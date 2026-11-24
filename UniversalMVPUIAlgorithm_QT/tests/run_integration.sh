#!/bin/bash
# ============================================================================
#  UMVPQT GOD STATE — Entegrasyon Testleri (bagimsiz)
#  Qt6 + Qt5 hedef uygulamalari karsi UCLT-UCA test:
#    - Qt tespiti + tam surum
#    - Form bulma (Form1/Form2)
#    - Widget tespiti: buton/label/lineedit/combobox/checkbox
#    - Nesne ozellikleri: text, objectName, pos/size, visible
#    - COMBOBOX: item listesi + SECILI deger
#    - EVENT analizi: clicked -> slot cozumu (onKaydet/onBtnEventli)
#    - BOS buton (event YOK) tespiti
#    - HANDLER kod adresleri + .asm dump
#    - MONITOR diff (form acilma/kapanma)
# ============================================================================
set -u
QTROOT=${QTROOT:-/home/z/my-project/toolchain/root}
DIR=$(cd "$(dirname "$0")/.." && pwd)
BIN=$DIR/umvpqt_cli
LD="LD_LIBRARY_PATH=$QTROOT/usr/lib/x86_64-linux-gnu"
PASS=0; FAIL=0

ok()  { PASS=$((PASS+1)); echo "  [PASS] $1"; }
bad() { FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }

check() { # check <dosya> <desen> <mesaj>
    if rg -q "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3 (desen: $2)"; fi
}

run_target() { # run_target <6|5> -> PID yazar
    local era=$1
    export QT_QPA_PLATFORM=offscreen
    export QT_PLUGIN_PATH=$QTROOT/usr/lib/x86_64-linux-gnu/qt$era/plugins
    export LD_LIBRARY_PATH=$QTROOT/usr/lib/x86_64-linux-gnu
    $DIR/demo_qt$era >/dev/null 2>&1 &
    echo $!
}

echo "================ UMVPQT ENTTEGRASYON TESTLERI ================"

for ERA in 6 5; do
    echo ""
    echo "--- Qt$ERA hedefi ---"
    PID=$(run_target $ERA)
    sleep 2
    [ -n "$PID" ] && [ "$PID" != "" ] || { bad "surec baslatilamadi"; continue; }

    R=/tmp/umvp_report_qt$ERA.txt
    timeout 120 env LD_LIBRARY_PATH=$QTROOT/usr/lib/x86_64-linux-gnu \
        $BIN --pid $PID --txt $R --json /tmp/umvp_report_qt$ERA.json \
        --asm-dir /tmp/umvp_asm_qt$ERA >/dev/null 2>&1

    if [ ! -s "$R" ]; then bad "rapor uretilemedi"; kill $PID 2>/dev/null; continue; fi
    ok "rapor uretildi"

    # ---- tespit ----
    if [ $ERA = 6 ]; then
        check $R "surum: 6\.8\.2" "Qt6 tam surum tespiti (qVersion disasm)"
    else
        check $R "surum: 5\.15\.15" "Qt5 tam surum tespiti (qVersion disasm)"
    fi

    # ---- formlar ----
    check $R "FORM: UMVPQT Demo Ana Form" "Form1 (AnaPencere) bulundu"
    check $R "class=AnaPencere name=Form1_AnPencere" "Form sinif + objectName"
    check $R "Form2_Ayarlar" "Form2 (AyarDialog) agacta"

    # ---- widget'lar ----
    check $R "QPushButton \[name=btnEventli\]" "btnEventli tespit"
    check $R "QPushButton \[name=btnBos\]" "btnBos (bos buton) tespit"
    check $R "QLabel \[name=lblBaslik\]" "lblBaslik tespit"
    check $R "QLineEdit \[name=editAd\]" "editAd (QLineEdit) tespit"
    check $R "QComboBox \[name=comboSeviye\]" "comboSeviye tespit"
    check $R "QCheckBox \[name=chkOtomatik\]" "chkOtomatik tespit"
    check $R "MyCanvas" "MyCanvas (ozel paintEvent widget'i) tespit"

    # ---- ozellikler ----
    check $R "text='Event'li Buton" "buton text okuma"
    check $R "text='Bos Buton" "bos buton text okuma"
    check $R "edit='umvpqt_test_metni'" "QLineEdit metni (QWidgetLineControl)"
    check $R "size=420x420" "form geometry (420x420)"
    check $R "visible=EVET" "gorunurluk tespiti"

    # ---- combobox ----
    check $R "COMBO \(4\)" "combobox item sayisi (4)"
    check $R "Zor" "combobox item metni"
    check $R "SECILI: Zor \(index 2\)" "combobox SECILI deger + index"
    check $R "Turkce.*English.*Deutsch.*Francais" "4 item tam liste"

    # ---- event tespiti (GOD) ----
    check $R "CONNECT clicked\(\) -> AnaPencere::onBtnEventli\(\)" "clicked->onBtnEventli baglantisi"
    if [ $ERA = 6 ]; then
        check $R "CONNECT clicked\(\) -> AyarDialog::onKaydet\(\)" "clicked->onKaydet baglantisi"
    fi
    check $R "HANDLER\(slot\) AnaPencere::onBtnEventli" "slot handler kod adresi"
    check $R "HANDLER\(slot\) AnaPencere::onChkOtomatik" "checkbox slot handler"
    if [ $ERA = 6 ]; then
        check $R "HANDLER\(override\) paintEvent.*demo_qt6" "MyCanvas paintEvent OVERRIDE adresi"
    fi
    # bos buton: btnBos EVENT YOK (clicked baglantisi yok)
    python3 - "$R" <<'PYEOF' && ok "btnBos: event YOK dogrulandi (bos buton)" || bad "btnBos event analizi"
import sys, re
r = open(sys.argv[1], encoding='utf8', errors='ignore').read()
# btnBos satiri ile HANDLER(slot) onBtnEventli arasinda btnEventli'nin EVENT VAR olmali;
# btnBos icin clicked baglantisi OLMAMALI
btn_bos = re.search(r'\+ QPushButton \[name=btnBos\].*?(?=\+ [A-Z])', r, re.S)
if not btn_bos: sys.exit(1)
seg = btn_bos.group(0)
if 'CONNECT clicked' in seg: sys.exit(1)   # clicked baglantisi varsa hata
sys.exit(0)
PYEOF
    python3 - "$R" <<'PYEOF' && ok "btnEventli: EVENT VAR dogrulandi" || bad "btnEventli event analizi"
import sys, re
r = open(sys.argv[1], encoding='utf8', errors='ignore').read()
btn = re.search(r'\+ QPushButton \[name=btnEventli\].*?(?=\+ [A-Z])', r, re.S)
if not btn: sys.exit(1)
if 'CONNECT clicked() -> AnaPencere::onBtnEventli()' not in btn.group(0): sys.exit(1)
sys.exit(0)
PYEOF

    # ---- sinif envanteri ----
    check $R "AnaPencere.*metaObject=0x[1-9a-f]" "AnaPencere staticMetaObject cozumlu"
    check $R "AnaPencere.*zincir: QMainWindow <- QWidget <- QObject" "AnaPencere sinif zinciri"
    check $R "QPushButton.*QAbstractButton <- QWidget" "QPushButton sinif zinciri"

    # ---- JSON ----
    if [ -s /tmp/umvp_report_qt$ERA.json ]; then
        ok "JSON rapor uretildi"
        python3 -c "import json; json.load(open('/tmp/umvp_report_qt$ERA.json'))" 2>/dev/null \
            && ok "JSON gecerli" || bad "JSON bozuk"
    else
        bad "JSON rapor yok"
    fi

    # ---- .asm dump ----
    if ls /tmp/umvp_asm_qt$ERA/*.asm >/dev/null 2>&1; then
        N=$(ls /tmp/umvp_asm_qt$ERA/*.asm | wc -l)
        ok "asm dump ($N dosya)"
        if rg -q "mov|push|lea" /tmp/umvp_asm_qt$ERA/*.asm 2>/dev/null; then
            ok "asm icerigi gercek komutlar"
        else bad "asm bos"
        fi
    else
        bad "asm dump yok"
    fi

    # ---- MONITOR (yalniz Qt6: zamanlama) ----
    if [ $ERA = 6 ]; then
        echo "  --- monitor testi ---"
        MON=/tmp/umvp_monitor_qt6.txt
        timeout 60 env LD_LIBRARY_PATH=$QTROOT/usr/lib/x86_64-linux-gnu \
            $BIN --pid $PID --monitor --interval 500 --count 4 > $MON 2>/dev/null
        if rg -q "DIFF" $MON 2>/dev/null; then ok "monitor dongusu calisti"; else bad "monitor calismadi"; fi
    fi

    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
done

echo ""
echo "================ SONUC: PASS=$PASS FAIL=$FAIL ================"
[ $FAIL -eq 0 ] && echo "TUM TESTLER GECTI — GOD STATE" || echo "BAZI TESTLER BASARISIZ"
exit $([ $FAIL -eq 0 ] && echo 0 || echo 1)
