# UMVPQT — UniversalMVPUIAlgorithm_QT

## MVP GOD STATE LEVEL QT UI ANALYSIS SDK

ImGui versiyonu ([UniversalMVPUIAlgorithm](https://github.com/0xByteDeveloper/UniversalMVPUIAlgorithm))'nun
**QT kardeşi**: QT ile kodlanmış menüye sahip herhangi bir EXE'yi açıp PID'sini seçtiğinizde,
**PDB olmadan, salt harici (external) bellek okuma + derin disassembly analiziyle**:

- **kaç form var** (Form1, Form2...), **şu an hangi form açık/gizli**
- her formdaki **tüm objeler** (QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, ...)
- objelerin **özellikleri**: text, objectName, konum (pos), boyut (size), görünürlük
- **combobox değerleri** ve **şu an seçili olan değer** (index + metin)
- **EVENT tespiti**: `clicked()` sinyaline bağlı slot **VAR MI YOK MU** (boş buton tespiti!)
- event handler'ların **çözülmüş adları**: `AnaPencere::onBtnEventli()`, `AyarDialog::onKaydet()`
- handler kod bloklarının **başlangıç/bitiş adresleri + .asm disassembly dump'u**
- `paintEvent` / `mousePressEvent` gibi **virtual override tespiti** (MyCanvas örneği)
- **monitor modu**: ekranda yeni bir şey çıkarsa (yeni form/widget/meto değişimi) DIFF olarak yakalanır
  — **ekran görüntüsü ALMAADAN**, tamamen bellek çözümlemesiyle

```
$ umvpqt_cli --pid 1234
[+] Qt tespit edildi: Qt6 (surum 6.8.2)
[*] QT 6 | surum 6.8.2 | QObject:194 | Widget:29 | Form:1 | Sinif:86 | Baglanti:29

FORM: UMVPQT Demo Ana Form  [class=AnaPencere name=Form1_AnPencere]
  adres=0x5575...  pos=2,2  size=420x420  visible=EVET
    + QPushButton [name=btnEventli] text='Event'li Buton (Tikla)'  pos=9,99 size=402x22
      CONNECT clicked() -> AnaPencere::onBtnEventli() [auto]
      HANDLER(slot) AnaPencere::onBtnEventli()  [0x...b8ad94 .. 0x...b8adda] demo_qt6
    + QPushButton [name=btnBos] text='Bos Buton (event YOK)'
      EVENT: YOK (bos buton)                       ← handler'sız buton!
    + QComboBox [name=comboSeviye] ...
      COMBO (4):   Kolay   Orta >*Zor   IMKANSIZ
      SECILI: Zor (index 2)
```

## Test Sonucu

`tests/run_integration.sh` — **Qt 6.8.2 ve Qt 5.15.15 hedeflerine karşı 69/69 test PASS**:
tespit, formlar, widget'lar, özellikler, combobox, event'ler, handler adresleri, asm dump,
JSON rapor, monitor diff — hepsi iki Qt çağında da doğrulandı (sandbox, offscreen platform).

## Nasıl Çalışır (GOD STATE algoritma özeti)

1. **Qt tespiti**: süreç modülleri (Qt5Core/Qt6Core...) + `qVersion()` export'unun
   disassembly'i (endbr64/lea/mov+ret desenleri) → **tam sürüm** ("6.8.2"), metaobject
   revision imzası → çağ (Qt4/5/6).
2. **Layout çözümü**: `tools/gen_layout` offsetof-probe'u Qt private header'larıyla
   derlenip **tam offsetof/sizeof DB** üretir (Qt 5.15 + Qt 6.8 gömülü). Bilinmeyen
   sürümler için genişlik-imzalı 32-bit rescaler + runtime kalibrasyon (q_ptr geri-bağ
   invariant'ları).
3. **Instance taraması**: heap RW-anon bölgelerinde GOD invariant:
   `X bir QObject <=> *(X+ptr) = D ve *(D+ptr) = X` (q_ptr geri-bağı) + bilinen
   vtable değerleriyle (modül sembollerinden `_ZTV7QWidget` vb.) **vtable-anchored** tarama.
4. **Sınıf çözümü**: vtable → (a) modül sembol tablosu (`_ZTV7QPushButton` /
   `??_7QPushButton@@6B@`), (b) vtable[metaObject-slot] thunk çözümlemesi
   (endbr64/LEA/MOV+ret veya dallı kod için **capstone rip-göreli taraması**),
   (c) **RTTI** (`vtable[-1]` typeinfo demangle) — app sınıfları dahil.
5. **QMetaObject parse**: bellekteki staticMetaObject → stringdata/data dizileri çağa göre
   çözülür (Qt6: offset/length uint çiftleri, Qt5: QByteArrayData tabloları, Qt4: char blob),
   tüm metod/sinyal/slot/property adları + superdata zinciri çıkarılır.
6. **Event tespiti**: `QObjectPrivate::connections → ConnectionData → SignalVector →
   Connection` yürüyüşü: her bağlantının sender/receiver/callFunction/method index'i okunur;
   **global index zincir çözümlemesiyle** `clicked() -> AnaPencere::onBtnEventli()` gibi
   tam imzalar üretilir. PMF bağlantılarında QPrivateSlotObject içindeki pointer-to-member
   değerinden **slot'un gerçek kod adresi** çıkarılır.
7. **Handler kod çözümü**: her sınıfın `qt_static_metacall` fonksiyonu capstone ile
   disassemble edilir; `cmp id,N; je caseN` zincirlerinden **metod index → slot fonksiyon
   adresi** haritası çıkarılır → başlangıç/bitiş adresleri (sembol tablosu + ilk-ret
   sınırıyla) ve **.asm dump** üretilir.
8. **Override tespiti**: QWidget vtable'ı + `QWidget::paintEvent` vb. sembol adreslerinden
   slot indeksleri ampirik hesaplanır; nesnenin vtable'ında farklı giriş = override →
   handler adresi + disasm.
9. **Monitor**: yeniden tarama + adres bazlı diff → `[YENI FORM]`, `[YENI WIDGET]`,
   `[METIN DEGISIMI]`, `[GORUNURLUK]`, `[COMBO SECIMI]` olayları.

Detay: `docs/QT_GOD_RESEARCH.md`, `docs/ALGORITHM.md`.

## Yapı (XPRO aynası)

```
include/umvpqt/    SDK başlıkları (types, process, module, qt_layouts, qt_metaobject,
                   qt_scan, qt_strings, qt_connections, qt_items, disasm, analyzer, report)
src/               uygulama + gömülü layout DB'ler (generated/qt_layout_db_qt{5,6}.h)
cli/main.cpp       umvpqt_cli
tools/gen_layout/  offsetof probu — herhangi bir Qt'ya karşı derlenip DB üretir
tests/demo_target/ test hedefi: 2 form, event'li/event'siz butonlar, combobox'lar,
                   paintEvent override'lı özel widget, zamanlanmış form aç/kapa
tests/run_integration.sh   69 testlik uçtan uca doğrulama
```

## Kullanım

```bash
umvpqt_cli --list                          # süreç listesi
umvpqt_cli --pid N                         # analiz + konsol raporu
umvpqt_cli --pid N --json r.json --txt r.txt --asm-dir asm/
umvpqt_cli --name demo_qt_app              # isimle seçim
umvpqt_cli --pid N --no-live               # sadece kod analizi
umvpqt_cli --pid N --no-code               # sadece bellek taraması
umvpqt_cli --pid N --monitor --interval 500 --count 20   # izleme (diff)
```

## Platform / Mimari

- **Windows**: Toolhelp32 + ReadProcessMemory + PE export tablosu (bellekten) ile
  sembol çözümü (MSVC mangled: `??_7X@@6B@`, `?staticMetaObject@...`).
- **Linux**: /proc/pid/maps + process_vm_readv + diskteki ELF .dynsym/.symtab.
- **32-bit hedefler**: 64-bit tablodan genişlik-imzalı rescale (pointer 8→4) + aynı
  invariant'lar; testler sandbox'ta 64-bit üzerinden yapıldı (ortam 32-bit Windows
  çalıştıramıyor).

## Bağımlılıklar

- C++17 derleyici
- [Capstone](https://www.capstone-engine.org/) (disassembly) — BSD-3
- Qt SDK yalnızca `tools/gen_layout` ve test hedefi için gerekir; tarayıcı kendisi Qt'ye
  **bağlı değildir** (saf bellek okuma).

## Lisans

MIT (bu repo) — Capstone BSD-3, Qt LGPL/GPL (test hedefleri derlemek için).
