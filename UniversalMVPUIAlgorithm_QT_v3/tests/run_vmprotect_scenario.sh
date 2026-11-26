#!/bin/bash
# ============================================================================
#  UMVPQT GOD STATE — VMProtect-benzeri senaryo E2E testi
#  Kullanicinin gercek is akisini (Test_64.exe + VMProtect 3.9.4) mock hedef
#  uzerinden UQI-AGENT ile otomatiklestirir:
#    - sol tab'dan Options'a gir, Memory protection YES yap, derle, yeniden adlandir
#    - Import protection / Antidebug / Resource / Memory limitation tek tek
#    - hepsi acik derle
#    - MovePlayer ekle (modal Add function dialog'i: ara + sec + OK)
#    - MovePlayer ULTRA / MUTATION / VIRTUALIZATION derle
#    -beklenen dosya adlari + ayar yanlari dogrulanir
# ============================================================================
set -u
QTROOT=${QTROOT:-/home/z/my-project/toolchain/root}
DIR=$(cd "$(dirname "$0")/.." && pwd)
OUT=${VMP_OUT:-/tmp/vmp_out}
PASS=0; FAIL=0

ok()  { PASS=$((PASS+1)); echo "  [PASS] $1"; }
bad() { FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }

echo "================ UMVPQT VMPROTECT SENARYO TESTI ================"

# ---- hazirlik ----
rm -rf "$OUT"; mkdir -p "$OUT"
cp /home/z/my-project/upload/Test_64.exe "$OUT/Test_64.exe" 2>/dev/null || {
    printf 'MOCK' > "$OUT/Test_64.exe"; echo "  (Test_64.exe bulunamadi — sahte kullanildi)";
}

export QT_QPA_PLATFORM=offscreen
export QT_PLUGIN_PATH=$QTROOT/usr/lib/x86_64-linux-gnu/qt6/plugins
export LD_LIBRARY_PATH=$QTROOT/usr/lib/x86_64-linux-gnu
export VMP_OUT=$OUT
export VMP_MOCK_OUT=$OUT
export VMP_MOCK_TARGET=$OUT/Test_64.exe

"$DIR/vmprotect_mock" >/dev/null 2>&1 &
MOCKPID=$!
sleep 2
if ! kill -0 $MOCKPID 2>/dev/null; then bad "vmprotect_mock baslamadi"; echo "SONUC: FAIL"; exit 1; fi
ok "vmprotect_mock calisiyor (pid $MOCKPID)"

# ---- senaryo ----
LOG=/tmp/vmp_agent_log.json
timeout 300 env VMP_OUT=$OUT LD_LIBRARY_PATH=$LD_LIBRARY_PATH \
    "$DIR/uqt_agent" --name vmprotect_mock --allow-shell \
    --script "$DIR/examples/vmprotect_scenario.json" > $LOG 2>/tmp/vmp_agent_err.txt
RC=$?

# ---- komut yanitlari ----
NRESP=$(rg -c '"ok":true' $LOG 2>/dev/null || echo 0)
NFAIL=$(rg -c '"ok":false' $LOG 2>/dev/null || echo 0)
echo "  agent yanit: ok=$NRESP hata=$NFAIL rc=$RC"
if [ "$NFAIL" = "0" ] && [ "$RC" = "0" ]; then ok "senaryo tum komutlari OK"; else bad "senaryo hata iceriyor (bkz. $LOG / /tmp/vmp_agent_err.txt)"; fi

# Qt surum tespiti
rg -q '"qt_version":"6\.8\.2"' $LOG 2>/dev/null && ok "Qt6 tam surum tespiti (6.8.2)" || bad "Qt surumu"

# ---- cikti dosyalari ----
expected=(
  "Test_64_MemoryProtection.vmp.exe"
  "Test_64_ImportProtection.vmp.exe"
  "Test_64_Antidebug.vmp.exe"
  "Test_64_ResourceProtection.vmp.exe"
  "Test_64_MemoryLimitation.vmp.exe"
  "Test_64_ALL.vmp.exe"
  "Test_64_MovePlayer_ULTRA_ImportProtection.vmp.exe"
  "Test_64_MovePlayer_ULTRA_ALL.vmp.exe"
  "Test_64_MovePlayer_ULTRA.vmp.exe"
  "Test_64_MovePlayer_MUTATION.vmp.exe"
  "Test_64_MovePlayer_VIRTUALIZATION.vmp.exe"
)
for f in "${expected[@]}"; do
    if [ -s "$OUT/$f" ]; then ok "cikti: $f"; else bad "cikti yok: $f"; fi
done

# ---- ayar dogrulama (yan yansi JSON'lardan) ----
python3 - "$OUT" <<'PYEOF' && ok "ayar yanitlari dogrulandi (options + fonksiyonlar)" || bad "ayar dogrulama"
import sys, json, os
out = sys.argv[1]
def j(n):
    p = os.path.join(out, n + ".json")
    return json.load(open(p)) if os.path.exists(p) else None

def check(n, opts=None, fns=None):
    d = j(n)
    assert d, f"yok: {n}"
    o = d["options"]
    exp = {"memoryProtection": False, "importProtection": False, "antidebug": False,
           "resourceProtection": False, "memoryLimitation": False, "packOutput": False}
    for k, v in (opts or {}).items(): exp[k] = v
    for k, v in exp.items(): assert o[k] == v, f"{n}:{k}={o[k]} beklenen {v}"
    g = d.get("functions", [])
    if fns is None: assert g == [], f"{n} fonksiyon beklenmiyordu: {g}"
    else:
        assert len(g) == len(fns), f"{n} fonksiyon sayisi"
        for got, (name, mode) in zip(g, fns):
            assert got["name"] == name and got["mode"] == mode, f"{n} fonksiyon: {got}"
    return True

check("Test_64_MemoryProtection.vmp.exe", {"memoryProtection": True})
check("Test_64_ImportProtection.vmp.exe", {"importProtection": True})
check("Test_64_Antidebug.vmp.exe", {"antidebug": True})
check("Test_64_ResourceProtection.vmp.exe", {"resourceProtection": True})
check("Test_64_MemoryLimitation.vmp.exe", {"memoryLimitation": True})
check("Test_64_ALL.vmp.exe", {"memoryProtection": True, "importProtection": True,
                              "antidebug": True, "resourceProtection": True,
                              "memoryLimitation": True})
check("Test_64_MovePlayer_ULTRA_ImportProtection.vmp.exe", {"importProtection": True},
      [("MovePlayer", "Ultra")])
check("Test_64_MovePlayer_ULTRA_ALL.vmp.exe", {"memoryProtection": True, "importProtection": False,
      "antidebug": True, "resourceProtection": True, "memoryLimitation": True},
      [("MovePlayer", "Ultra")])
check("Test_64_MovePlayer_ULTRA.vmp.exe", fns=[("MovePlayer", "Ultra")])
check("Test_64_MovePlayer_MUTATION.vmp.exe", fns=[("MovePlayer", "Mutation")])
check("Test_64_MovePlayer_VIRTUALIZATION.vmp.exe", fns=[("MovePlayer", "Virtualization")])
sys.exit(0)
PYEOF

# MovePlayer listede mi (agent'in rescan ciktisinda)
rg -q "MovePlayer" $LOG 2>/dev/null && ok "MovePlayer ekranda (label/agent ciktisi)" || echo "  (info) MovePlayer rescan ciktisinde yok"

kill $MOCKPID 2>/dev/null
wait $MOCKPID 2>/dev/null

echo ""
echo "================ SONUC: PASS=$PASS FAIL=$FAIL ================"
[ $FAIL -eq 0 ] && echo "VMPROTECT SENARYOSU TAMAMI — GOD STATE AGENT" || echo "SENARYODA HATA VAR"
exit $([ $FAIL -eq 0 ] && echo 0 || echo 1)
