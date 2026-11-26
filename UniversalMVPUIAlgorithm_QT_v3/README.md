# UMVPQT — UniversalMVPUIAlgorithm_QT

## v3 "GOD STATE PROVEN" — statik-Qt + wine + GERÇEK VMProtect derlemesi
### MVP GOD STATE LEVEL QT UI ANALYSIS + CONTROL SDK
### (ImGui kardeşi: https://github.com/0xByteDeveloper/UniversalMVPUIAlgorithm)

Qt ile kodlanmış menüye sahip herhangi bir EXE'yi açıp PID'sini seçtiğinizde,
**PDB olmadan, salt harici (external) bellek okuma/yazma + derin disassembly
analiziyle**:

- **kaç form var** (Form1, Form2...), **şu an hangi form açık/gizli** (QDialog
  gibi parent'lı pencereler dahil — Qt::Window bayrağı tespiti)
- her formdaki **tüm objeler** (QPushButton, QLabel, QLineEdit, QComboBox,
  QCheckBox, QListWidget, ...)
- objelerin **özellikleri**: text, objectName, konum (pos), boyut (size),
  görünürlük, tooltip
- **combobox değerleri** ve **şu an seçili olan değer** (index + metin)
- **EVENT tespiti**: `clicked()` sinyaline bağlı slot **VAR MI YOK MU**
  (boş buton tespiti!) — sadece combobox değil **BÜTÜN objelerde**
- event handler'ların **çözülmüş adları**: `AnaPencere::onBtnEventli()`
- handler kod bloklarının **başlangıç/bitiş adresleri + .asm disassembly dump'u**
- `paintEvent` / `mousePressEvent` gibi **virtual override tespiti**
- **monitor modu**: yeni form/widget/metin değişimi DIFF olarak yakalanır
  — **ekran görüntüsü ALMADAN**, tamamen bellek çözümlemesiyle

### YENİ: UZAKTAN KONTROL (INVOKE) — "button1'e basilsın"
- **uqt_agent**: yapay zekanın tool'u bir uzvu gibi kullanması için JSON-lines
  komut protokolu: `click`, `setcombo`, `settext`, `selectrow`, `check`,
  `waitform`, `rescan`, `sh`... (`docs/AGENT.md`)
- Linux: **ptrace motoru** — GUI thread'i kendi üzerinde çağrı çalıştırır
  (Qt thread-affinity güvenli), iç-içe MODAL diyalog akışları destekli
- Windows: **CreateRemoteThread + RWX stub** (64-bit) — `process_win.cpp`
- Semboller PDB'siz: Itanium + MSVC mangled + ad-taraması

```
$ uqt_agent --pid 1234
{"cmd":"attach","pid":1234}                          → baglan
{"cmd":"analyze"}                                    → tam tarama
{"cmd":"forms"}                                     → formlar + objeler
{"cmd":"click","name":"button1"}                     → TIKLA (handler hedefte calisir!)
{"cmd":"setcombo","text":"Memory protection","value":"Yes"}   → combobox degistir
{"cmd":"settext","name":"editSearch","value":"MovePlayer"}  → metin yaz
{"cmd":"waitform","title":"Add function"}            → modal diyalog bekle
```

```
$ umvpqt_cli --pid 1234
[+] Qt tespit edildi: Qt6 (surum 6.8.2)
[*] QT 6 | surum 6.8.2 | QObject:194 | Widget:29 | Form:1 | Sinif:86 | Baglanti:29
FORM: UMVPQT Demo Ana Form  [class=AnaPencere name=Form1_AnPencere]
    + QPushButton [name=btnEventli] text='Event'li Buton (Tikla)'
      CONNECT clicked() -> AnaPencere::onBtnEventli() [auto]
      HANDLER(slot) AnaPencere::onBtnEventli()  [0x...l8ad94 .. 0x...l8adda]
    + QPushButton [name=btnBos] text='Bos Buton (event YOK)'
      EVENT: YOK (bos buton)                       ← handler'sız buton!
    + QComboBox [name=comboSeviye] ...
      COMBO (4):   Kolay   Orta >*Zor   IMKANSIZ
      SECILI: Zor (index 2)
```

## Test Sonucu

- `tests/run_integration.sh` — **Qt 6.8.2 ve Qt 5.15.15'e karşı 69/69 PASS**
- `tests/run_vmprotect_scenario.sh` — **VMProtect-benzeri hedefe karşı 15/15
  PASS**: kullanıcının tanımladığı GERÇEK VMProtect iş akışının (Options →
  Memory Protection YES → Compile → yeniden adlandır; tek-tek özellikler;
  ALL; Add Function modal diyalogu → ara → seç → OK → ULTRA/MUTATION/
  VIRTUALIZATION) uçtan uca otomasyonu, 81/81 ajan komutu OK + 11 çıktı
  dosyası + ayar yanıkları doğrulandı (`examples/vmprotect_scenario.json`).
- invoke motoru (ptrace uzak mmap + uzak çağrı + iç-içe modal) sandbox'ta
  GERÇEK Qt süreçlerine karşı doğrulandı.

## Nasıl Çalışır (GOD STATE algoritma özeti)

1. **Qt tespiti**: modüller (Qt5Core/Qt6Core...; statik Qt'de export imzası) +
   `qVersion()` export'unun disassembly'i → tam sürüm; metaobject revision → çağ.
2. **Layout çözümü**: `tools/gen_layout` offsetof-probe'u → gömülü
   offsetof/sizeof DB (Qt 5.15 + Qt 6.8); 32-bit rescaler + runtime kalibrasyon.
3. **Instance taraması**: `X bir QObject <=> *(X+ptr)=D ve *(D+q_ptr)=X`
   (q_ptr geri-bağı) + vtable-anchored tarama; **bölge listesi her taramada
   tazelenir** (stack-büyümesi/yeni arena'lar → QDialog gibi stack-allocated
   pencereler görünür).
4. **Sınıf çözümü**: vtable → (a) modül sembolleri (`_ZTV7QWidget` /
   `??_7QWidget@@6B@`), (b) vtable[metaObject-slot] thunk çözümlemesi
   (capstone rip-göreli tarama), (c) **RTTI** — app sınıfları dahil.
5. **QMetaObject parse**: stringdata/data dizileri çağa göre (Qt6 uint-çiftleri,
   Qt5 QByteArrayData, Qt4 char blob) — metod/sinyal/slot/property adları +
   superdata zinciri.
6. **Event tespiti**: `connections → ConnectionData → SignalVector →
   Connection` yürüyüşü: sender/receiver/callFunction/metod index →
   `clicked() -> AnaPencere::onBtnEventli()` tam imzaları; PMF bağlantılarında
   slot'un gerçek kod adresi.
7. **Handler kod çözümü**: her sınıfın `qt_static_metacall` fonksiyonu
   capstone ile disassemble → metod index → slot adresi → base–end + .asm dump.
8. **Override tespiti**: QWidget vtable'ı + sanal slot indeksleri → farklı
   giriş = override (paintEvent/mousePressEvent...).
9. **Form tespiti**: parent'sız VEYA **Qt::Window bayraklı** pencereler
   (QDialog dahil — windowTitle çözümlenir).
10. **INVOKE (yeni)**: ptrace (Linux) / CreateRemoteThread + stub (Windows):
    `QAbstractButton::click()`, `QComboBox::setCurrentIndex(int)`,
    `QLineEdit::setText(QString)` (QString hedef süreçte inşa edilir —
    paylaşılabilir refcount), `QListWidget::setCurrentRow(int)`...
    Modal diyalog açan çağrılar *pending* kalır, GUI serbest bırakılır,
    iç-içe çağrılar aynı GUI thread'ine enjekte edilir (64KB'lık ayrı yığın
    bölgeleriyle); biten çağrılar kendi durdurma noktalarından devam eder.
11. **Monitor**: yeniden tarama + adres bazlı diff → `[YENI FORM]`,
    `[YENI WIDGET]`, `[METIN DEGISIMI]`, `[COMBO SECIMI]`, `[GORUNURLUK]`.

Detay: `docs/ALGORITHM.md`, `docs/QT_GOD_RESEARCH.md`, `docs/AGENT.md`,
`docs/VMPROTECT_PROFILE.md`.

## Yapı (XPRO aynası)

```
include/umvpqt/    SDK başlıkları (types, process, module, qt_layouts, qt_metaobject,
                   qt_scan, qt_connections, qt_items, qt_strings, disasm, analyzer,
                   report, json, invoke, agent)
src/               uygulama + gömülü layout DB'ler + invoke_linux + invoke_win +
                   process_linux + process_win + agent
cli/main.cpp       umvpqt_cli (pasif analiz)
cli/agent_main.cpp uqt_agent (YAPAY ZEKA sürücü CLI)
tools/gen_layout/  offsetof probu — herhangi bir Qt'ya karşı derlenip DB üretir
tests/demo_target/ test hedefi: 2 form, event'li/event'siz butonlar, combobox'lar,
                   paintEvent override'lı özel widget, zamanlanmış form aç/kapa
tests/vmprotect_mock/  VMProtect-benzeri mock (sol/sağ tab, Options combobox'ları,
                   Add function MODAL diyalogu, Compile → çıktı + ayar yanığı)
tests/run_integration.sh        69 testlik uçtan uca doğrulama (Qt5+Qt6)
tests/run_vmprotect_scenario.sh  VMProtect iş-akışı senaryosu (15 doğrulama)
examples/vmprotect_scenario.json  kullanıcının tanımladığı TAM akış (senaryo)
docs/             ALGORITHM, QT_GOD_RESEARCH, AGENT (AI protokol), VMPROTECT_PROFILE
```

## Kullanım

```bash
umvpqt_cli --list                          # süreç listesi
umvpqt_cli --pid N                         # analiz + konsol raporu
umvpqt_cli --pid N --json r.json --txt r.txt --asm-dir asm/
umvpqt_cli --pid N --monitor --interval 500 --count 20   # izleme (diff)

uqt_agent --list                           # süreç listesi
uqt_agent --pid N                          # JSON-lines REPL (docs/AGENT.md)
uqt_agent --name VMProtect --allow-shell  # isimle bağlan + shell izni
uqt_agent --pid N --script examples/vmprotect_scenario.json
```

## Platform / Mimari

- **Windows (üretim)**: Toolhelp32 + ReadProcessMemory + **bellekten PE export
  tablosu** (MSVC mangled `??_7X@@6B@`...); invoke: CreateRemoteThread + RWX
  stub (64-bit). CMakeLists.txt ile MSVC/MinGW derlemesi.
- **Linux (sandbox testi)**: /proc maps + process_vm_readv/writev + ptrace
  invoke; diskteki ELF .dynsym/.symtab.
- **32-bit hedefler**: genişlik-imzalı rescale; Linux invoke 64-bit hedef
  gerektirir (Windows stub'u 64-bit; 32-bit stub TODO).

## Bağımlılıklar

- C++17 derleyici
- [Capstone](https://www.capstone-engine.org/) (disassembly) — BSD-3
- Qt SDK yalnızca `tools/gen_layout` ve test hedefleri için gerekir; tarayıcı
  kendisi Qt'ye **bağlı değildir** (saf bellek erişimi).

## Lisans

MIT (bu repo) — Capstone BSD-3, Qt LGPL/GPL (test hedefleri derlemek için).


---
## V3 — GitHub birleşimi + gerçek VMProtect 3.9.4 kanıtları (sandbox/wine)

**x1 (repo karşılaştırması)**: GitHub'daki depoda iki dalga vardı — kökte eski
çekirdek (V307-3 statik-Qt tespit yamasıyla) ve `UniversalMVPUIAlgorithm_QT/`
alt dizininde ara sürüm. Bu proje (v2/v3) invoke+agent katmanlarıyla en
günceldi; **V307-3 yaması buraya taşındı** (qt_scan.cpp bellek-imza fallback'i)
ve şu geliştirmeler eklendi:

### V3.1 — Statik-Qt era seçimi
V307-3 statik tespitte Qt5'i sert kodluyordu. Artık metaobject revision
oylamasıyla era seçiliyor (rev 7→Qt5, 9+→Qt6) → layout DB doğru seçiliyor
→ widget taraması körleşmiyor.

### V3.2 — wine hedefleri için dört kritik katman
1. **win64 çağrı kuralı** (LinuxInvoker): wine PE kodu MS x64 ABI
   (rcx/rdx/r8/r9) — SysV değil. Ajan modül tablosunda .exe/.dll görünce
   anahtar otomatik açılır.
2. **qt_static_metacall slot invoke** (QtActor::callSlot): statik Qt'de
   export yok → `qt_static_metacall(_o, InvokeMetaMethod, _id, _a)` doğrudan
   çağrılır. MainWindow::addFunction() → **FunctionDialog bellekte açıldı**.
3. **XTEST giriş katmanı** (src/invoke_x11.cpp + ajan komutları
   `xkey/xclick/xtype/xwindows`): Windows SendMessage dengi — Qt olayları
   NATIVE işler. **F9 → gerçek derleme → 6,6 MB .vmp.exe.**
4. **Kararlılık**: findWidget form-cache, waitTarget süre denetimi,
   SIGSEGV fırtına-abort, fixSyscallRestart (wine pipe-read onarımı),
   gerçek-yığın çağrı çerçevesi.

### Kanıt tablosu (tamamı sandbox içinde, SS/OCR YOK)
- Gerçek VMProtect 3.9.4 (rootless wine + Xvfb): **4171 QObject / 391 widget /
  151 sınıf / MainWindow 82 slot** — bellek taramasıyla.
- MainWindow::addFunction(): **dialog bellekte açıldı** (rescan olayları).
- XTEST F9 → **Test_64_MemoryProtection.vmp.exe (6.631.323 bayt)**.
- tools/vmp_batch.sh → **11/11 isimlendirilmiş çıktı** (sandbox_proof/).
- Entegrasyon: **69/69 PASS** (Qt5+Qt6 mock) + 15/15 senaryo.

---

## V3.3 — tam nesne envanteri + Options bit haritası (kanıtlı)

**`objects` komutu** (YENİ): widget OLMAYAN QObject'ler dahil tam envanter —
bir Qt uygulamasının veri modeli (Property/Model/Manager sınıfları) artık
ajanla listelenebilir:

```
$ uqt_agent --pid $(pgrep VMProtect)
{"cmd":"attach","pid":N}
{"cmd":"analyze"}
{"cmd":"objects","class":"Property","fields":true,"raw":64}
→ 165 nesne: BoolProperty("Memory Protection"), EnumProperty("Debugger"),
   ValueProperty("Complexity"), CompilationTypeProperty("Compilation Type")...
   hepsi ad + yardım metniyle bellekten
```

**Options sekmesi = 24 özellik** (kullanıcının "20 civarı" tahmininin kesin
cevabı — bellekten: Virtual Machine 3 + File 4 + Detection 2 + Additional 6 +
Messages 5 + Licensing 4). **Kontrollü bit deneyi**: .vmp Options=N yükle →
BoolProperty değer baytını (gövde +0x38) bellekten izle → 6 bit↔özellik
eşleşmesi kesinleştirildi; 0x800 = **Virtualization Tools Detection** (eski
'MemoryLimitation' etiketi YANLIŞTI).

**V4 tam matris motoru** (`tools/vmp_batch_v4.sh`): Aile 1 (12 seçenek tek
tek + ALL, MovePlayer yok) + Aile 2 (aynısı MovePlayer ULTRA kalıcı) + Aile 3
(3 mod) = **29 gerçek .vmp.exe** — her biri wine64 + ajanın kendi XTEST F9'u
ile üretilir.
