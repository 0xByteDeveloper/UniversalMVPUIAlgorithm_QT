# UniversalMVPUIAlgorithm_QT

**MVP GOD STATE LEVEL QT UI ANALYSIS SDK** — Qt tabanlı herhangi bir EXE'nin süreç
belleğini derin analizle tarayan, formları (Form1/Form2...), widget'ları
(QPushButton, QComboBox, QLabel, QCheckBox, kullanıcı sınıfları...) ve bunların
**nesne ağacını, olay bağlantılarını (sinyal-slot), handler kod adreslerini
(base/end) + disassembly'sini** PDB OLMAKSIZIN, saf derin disassembly + canlı
bellek analiziyle çıkaran C++17 SDK ve CLI aracı. Ayrıca **INVOKE GOD MODE**:
`button1.click()` — tespit ettiği slot'u hedef süreçte GERÇEKTEN çağırır.

> Orijinal ImGui/XPRO sürümü: [UniversalMVPUIAlgorithm](https://github.com/0xByteDeveloper/UniversalMVPUIAlgorithm)

```
==============================================================================
UMVP-QT // UniversalMVPUIAlgorithm_QT — MVP GOD STATE QT UI ANALYSIS
Qt 5.15 | Qt 6.8 (moc revision 7..12) — PDB YOK, saf bellek + disassembly
==============================================================================
```

## Ne yapar?

1. **Süreç seçimi**: `--list` ile PID listesi, `--pid N` / `--name x.exe` ile hedef.
2. **Canlı bellek analizi (GOD STATE)**:
   * Heap'i **vtable → metaObject() thunk → QMetaObject** zinciriyle tarar;
     thunk'ın disassembly'sinden (`lea rax,[rip+X]; ret` / `mov rax,[rip+X]; ret`
     / `movabs rax,imm64; ret`) statik metaobject adresi çözülür.
   * **q_ptr == nesne adresi** değişmezi + QMetaObjectPrivate başlık sağlaması
     (revision 7..12, sınırlı sayılar) → yanlış pozitif neredeyse imkânsız.
   * `QObjectPrivate` (ExtraData/threadData/**connections**) okunur; children
     listesi (Qt5 QListData / Qt6 QArrayDataPointer) çözülür; **objectName**
     (QString: Qt5 24-bayt başlık / Qt6 {d,ptr,size}) UTF-16'dan çözülür.
   * QWidgetData (her iki Qt'de aynı layout): **crect (geometri), winId,
     windowFlags, görünürlük** — formlar (üst-düzey widget'lar) + aktif form.
3. **Olay tespiti (sinyal-slot bağlantı grafiği)**:
   * `ConnectionData → SignalVector → ConnectionList[i] → Connection` zinciri
     yürünür; her bağlantı için **signal adı, slot sahibi sınıf + slot adı**,
     bağlantı tipi (direct/queued/auto/blocking), functor mu (QSlotObjectBase)
     değil mi çıkar. **Olayı olmayan düğmeler/nesneler de listelenir ve
     "olay: YOK" olarak işaretlenir.**
4. **Derin disassembly (PDB YOK)**:
   * **`qt_static_metacall` switch çözümleyici** — üç dispatch deseninin hepsi:
     8-bayt mutlak jump table (`jmp [rT+idx*8]`), **gcc PIE göreli tablosu**
     (`lea rT,[rip+..]; movsxd rA,[rT+idx*4]; add rA,rT; jmp rA`) ve cmp-chain
     (`cmp idx,K; je caseK` — `test r,r` = 0 durumu dahil).
   * Her case gövdesindeki `call rel32` (veya kuyruk `jmp`) → **slot fonksiyon
     adresi**; inline edilmiş gövdeler "inlined" olarak dürüstçe raporlanır.
   * Handler **[base,end) aralığı** + tam disassembly listesi (`.asm` dump).
   * **Vtable override tespiti**: taban sınıf vtable'ı ile slot-slot
     karşılaştırma → `mousePressEvent`, `keyPressEvent`... override'ları.
5. **INVOKE GOD MODE — "button1'e basılsın"**:
   * `qt_static_metacall(obj, InvokeMetaMethod, localIdx, argv)` uzaktan
     çağrılır (Windows: CreateRemoteThread + position-independent shellcode;
     mock/test: in-process executor).
   * `emitSignal`: bağlantı grafiğini **QMetaObject::activate** mantığıyla
     yürür — direct bağlantıları gerçek slot'larıyla ateşler (functor'lar
     dahil: QSlotObjectBase impl çağrısı, Qt5/Qt6 imza farkına göre).
   * `click()` = clicked sinyali + click() slot'u; `readProperty` =
     text/currentIndex/currentText/count...; `comboItems` = itemText(i) döngüsü.
6. **Rapor**: XPRO tarzı Türkçe metin raporu + JSON + per-handler `.asm` dosyaları.

## Örnek çıktı (demo — `make demo`)

```
Hedef        : mock_qt_target (PID 4242) [x64]
Qt           : 5.15 ailesi (revision 8)  modul: Qt5Core.dll
Dogrulanmis QObject : 9  | baglanti: 3  | handler: 3
--- FORMLAR: 2 ----------------------------------------------------------
[0] "Form1"  (Form1)  [AKTIF] [GORUNUR]
    nesne=0x10002390  rect=(60,60,700,520)  winId=0x21a01
    widget'lar (6):
        1. QPushButton "button1"  text="Kaydet" (guven %70)  rect=(20,60,120,28)
           olay: clicked -> on_button1_clicked [direct]  handler=0x55fbb7b9fd80
           handler kod blogu: 0x55fbb7b9fd80..0x55fbb7b9fd88 (6 komut)  [qt_static_metacall, guven %90]
        3. QComboBox "combo1"  rect=(20,100,160,24)
           ogeler: A|B|C  secili: B
           olay: YOK (bagli handler yok)
        6. MyButton "myButton"  text="Ozel"  rect=(20,190,120,28)
           override: mousePressEvent
--- GOD MODE INVOKES -----------------------------------------------------
click(button1)      : ok=1  fired=2  [emit clicked + click() slot]
readProperty(text)  : "Kaydet"
combo currentIndex  : 1 / count=3
combo items (itemText invoke): A|B|C
```

## Derin bulgular (Qt SDK taramasından)

Bu SDK, qtbase kaynaklarının (5.15 ve 6.8 etiketleri) birebir doğrulanmış
yapı bilgisiyle yazıldı — her kritik yapı kaynaktan teyit edildi:

| Yapı | Qt 5.15 (x64) | Qt 6.8 (x64) |
| --- | --- | --- |
| QObjectData | 48 B; children@24 (QList 8 B) | 72 B; children@24 (QADP 24 B) |
| QObjectPrivate.connections | +64 | +88 |
| ExtraData::objectName | +40 (QT_NO_USERDATA alternatifi +32) | +96 |
| QMetaObject::d | 48 B; stringdata@8 (QByteArrayData[]) | 56 B; stringdata@8 (uint çiftleri), metaTypes@40 |
| QMetaObjectPrivate | 14 int; revision=8 | 14 int; revision 9..12 |
| method girdisi | 5 int (name,argc,params,tag,flags) | 6 int (+metaTypeOffset) |
| Connection | 88 B; bits@84: sig:27\|type:3\|slotObj:1 | 88 B; bits@84: sig:27\|type:2\|slotObj:1\|single:1 |
| ConnectionData→SignalVector | +8; listeler sv+16+16*(i+1) | aynı |
| QString | 8 B {d}; boyut@+4, offset@+16, UTF-16 | 24 B {d,ptr,size}; ptr@+8 UTF-16 |
| QWidgetData | winid@0, flags@12, crect@24 | **aynı** (5.15 = 6.8) |

* `tools/gen_layout/` her yapının **gerçek offsetof çıktısını** ABI replica
  başlıklarından (qtbase 5.15 / 6.8 alan sıraları 1:1) derleyip
  `src/qt_layout_db.h` üretir — **elle offset yazmak YOK**.
* Disassembly motoru gömülüdür (sıfır bağımlılık; Capstone varsa
  `USE_CAPSTONE=1` ile zenginleştirilebilir — çözümleyici desenleri aynıdır).

## Derleme

Gereksinimler: `g++ (C++17)`, `make` (Linux/macOS) veya MinGW-w64 (Windows).

```
make gen          # layout DB'yi offsetof'ten yeniden üret
make tests        # 6 bağımsız test ikilisi
make run          # testleri çalıştır (TÜMÜ PASS olmalı)
make cli          # bin/umvpqt_cli
make demo         # bin/umvpqt_demo — iki Qt ailesinde uçtan uca demo
make clean
```

Windows (MSYS2/MinGW): `mingw32-make` aynı hedefleri üretir
(`src/process_win.cpp` Toolhelp+RPM+EnumProcessModules+PE export çözümü;
invoke motoru CreateRemoteThread shellcode ile devreye girer).

## Kullanım

```
umvpqt_cli                       # interaktif: süreç listesi + PID seç
umvpqt_cli --list
umvpqt_cli --pid 1234 --json r.json --txt r.txt --asm-dir asm/
umvpqt_cli --name app.exe --family qt6
umvpqt_cli --pid 1234 --click button1            # "button1'e bas"
umvpqt_cli --pid 1234 --invoke button1.click()  # slot'u uzaktan çağır
umvpqt_cli --pid 1234 --emit button1.clicked     # sinyali ateşle
--family qt5|qt6    aileyi elle zorla
--no-live           bellek taramayı kapat
--no-code           disassembly/handler çözümünü kapat
--no-invoke         çağırma motorunu kapat (salt-okuma)
```

## Mimari

```
include/umvpqt/          SDK başlıkları
  types.h              veri modeli (AnalysisReport/FormInfo/WidgetInfo/HandlerInfo)
  process.h            IProcessReader (+bölge/modül + PE export çözümü)
  qt_layout.h          ABI layout DB API (Qt5/Qt6 × x64)
  qt_meta.h            QMetaObject çözümleyici (sınıf zinciri, method, property)
  qt_scan.h            QObject keşfi + ağaç + geometri + sezgisel metin/combobox
  qt_signals.h         bağlantı grafiği tarayıcı + handler adres çözümü
  disasm.h             pattern disassembler + qt_metacall çözümleyici
  qt_invoke.h          INVOKE GOD MODE (metacall/property/sinyal/zağ)
  analyzer.h           GOD STATE orkestratör
  report.h             metin/JSON/asm çıktıları
src/                    uygulamalar (+ qt_layout_db.h ÜRETİLMİŞ)
tools/gen_layout/       ABI replica başlıkları (qt5/qt6) + offsetof üreteci
cli/main.cpp            umvpqt_cli
tests/                  bağımsız testler + mock Qt süreç imajı + demo
  mock/mock_qt.*       sentetik Qt hedefi: gerçek ABI düzenleri, gerçek
                       derlenmiş metacall/handler fonksiyonları, bağlantı
                       grafiği — çözümleyici yalnızca IProcessReader görür
  test_layout.cpp      layout DB bütünlüğü (40 kontrol)
  test_metaobj.cpp     metaobject çözümü (54 kontrol)
  test_disasm.cpp      thunk + switch çözümleyici (28 kontrol)
  test_signals.cpp     olay VAR/YOK + handler (58 kontrol)
  test_analyzer.cpp    uçtan uca analiz (110 kontrol)
  test_invoke.cpp      god mode çağrılar (64 kontrol)
```

## Testler (bağımsız, sandbox'ta gerçek derlenmiş kod üzerinde)

| Test | Kapsam | Sonuç |
| --- | --- | --- |
| `test-layout` | DB vs replica offsetof | **PASS (40/40)** |
| `test-metaobj` | iki Qt ailesi: zincir/sinyal/slot/property/absolute index | **PASS (54/54)** |
| `test-disasm` | thunk desenleri + jump-table (mutlak & göreli) + cmp-chain | **PASS (28/28)** |
| `test-signals` | olay VAR/YOK; handler adres + aralığı + disassembly | **PASS (58/58)** |
| `test-analyzer` | uçtan uca: formlar, ağaç, metin, combobox, override, rapor | **PASS (110/110)** |
| `test-invoke` | click/emit/readProperty/itemItem — gerçek çağrılar | **PASS (64/64)** |
| `demo` | iki ailede tam boru hattı + god mode göstergesi | **OK** |

Toplam **354 bağımsız kontrol — 0 hata** (g++ -O2, x64). Mock hedef
Form1/Form2 + button1/button2/combo1/label1/check1/myButton(QTimer dahil)
içeren 9 QObject, 3 bağlantı (metot + functor), 1 vtable override içerir.

## Sınırlamalar / yol haritası

* **Invoke god mode uzaktan yürütme** yalnızca Windows derlemesinde
  (CreateRemoteThread) devrededir; Linux CLI salt-okumadır (ptrace tabanlı
  yürütücü yol haritasında). Testlerdeki MockRemoteExecutor aynı 5-argüman
  sıralamasını kullanır.
* Metin/combobox okuma: saf-bellek kipinde layout-hipotezli (güven %55-70);
  invoke kipinde %100 (gerçek metacall). MSVC hedeflerinde thunk/metacall
  desenleri MinGW/gcc ile aynı kalıpları izler; ek MSVC desenleri yol haritasında.
* 32-bit (x86) tabloları `gen_layout`'a `-m32` + i686 araç zinciri ile
  üretilebilir — bu sandbox yalnızca x64 çalıştırabildiğinden x86 canlı testi
  yapılmadı (orijinal UMVP ile aynı durum).
* Aktif form: görünürlük biti + alan büyüklüğü sezgiseli (Windows'ta winId
  üzerinden `GetForegroundWindow` çapraz-doğrulaması eklenebilir).

## Lisans

MIT. Bağımlılık: yok (gömülü pattern disassembler; Capstone opsiyonel BSD-3).
Qt kaynaklarından doğrulanan yapı bilgisi LGPL/GPL Qt'ye atıf ile kullanılır;
repoda Qt kodu bulunmaz (saha sıraları kendi replica başlıklarımızda).
