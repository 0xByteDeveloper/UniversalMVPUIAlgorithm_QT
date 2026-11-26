# VMProtect 3.9.4 Hedef Profili — UniversalMVPUIAlgorithm_QT

Bu dosya, aracın **gerçek VMProtect Ultimate 3.9.4** üzerinde çalışması için
gereken her şeyi bir araya toplar (kaynak: `universalAllver.rar` içindeki
`Allver_Collection/VMProtect Ultimate 3.9.4/` — sandbox'ta indirildi,
çıkarıldı ve statik olarak profillendi).

## 1. VMProtect.exe — ikili profil

| Özellik | Değer |
|---|---|
| Dosya | `VMProtect Ultimate 3.9.4/VMProtect.exe` (38.277.544 bayt) |
| Biçim | PE32+ (x86-64), GUI subsystem, 13 bölüm |
| Derleyici | MSVC (+ `/guard` — `.gfids` bölümü mevcut) |
| Qt bağlantısı | **STATİK** — Qt çalışma zamanı exe içinde (`\0` boyutlu bölümler + **`.qtmetad`** bölümü = moc QMetaObject verisi) |
| Kendi koruması | VMProtect ile paketli (`.xz@` sıkıştırma bölgesi ~36 MB, bölüm `RawSize=0`) |
| MSVC RTTI | Çalışma zamanında `.rdata` içinde (`??_R0?AVQPushButton@@...` tip tanımlayıcıları) |

### Bu profil araca ne söyler?
1. **Qt sürüm tespiti**: DLL listesi YOK (statik bağlantı) — QtDetector'ın
   `qVersion` export + metaobject-revision imza yolu devreye girer (arayüzdeki
   `qVersion` exportu statik Qt'de de exe export'udur; `--no-code` modu yerine
   tam tarama kullanın).
2. **Sembol çözümleme**: dış `libQt6Core` yok — TÜM Qt vtable'ları
   `VMProtect.exe` modülünün **bellekteki kendi görüntüsünde**. Aracın
   vtable-anchored taraması + RTTI (`??_R...`) + metaObject-thunk disassembly
   zinciri tam bu senaryo için tasarlandı: `??_7QPushButton@@6B@` yerine
   RTTI ve thunk çözümlemesi kullanılır.
3. **Invoke**: `QAbstractButton::click` / `QComboBox::setCurrentIndex` gibi
   Qt metotları exe içinde **statik bağlı** (export tablosunda OLMAYABİLİR).
   Bu durumda QtActor'ın 3. geçiş sembol taraması + qt_metacall
   çözümlemesi devreye girer; Windows invoker'ın `CreateRemoteThread` + stub
   yolu hedef exe içindeki fonksiyon adresini doğrudan çağırır.
4. **Kendi-koruma**: `.xz@` paketli bölge yalnızca disk görüntüsünde geçerli —
   süreç belleğinde Qt yapıları (vtable'lar, QMetaObject'ler, QObject
   instance'ları) tamamen geçerlidir; tarama PDB'siz çalışır.

## 2. UI etiket envanteri (Langs/en.lng — gerçek arayüz metinleri)

Senaryo (examples/vmprotect_scenario.json) bu GERÇEK etiketlerle eşleşir:

- Sol panel (QListWidget/QTabWidget): `Functions for Protection`, `Options`,
  `Licenses`, `Scripts`
- `Options` sayfası combobox'ları: **`Memory Protection`**, **`Import
  Protection`** (No/Yes), Antidebug, Resource Protection, Memory Limitation...
- `Functions` sayfası: `Add Function` düğmesi → **modal diyalog** (arama
  QLineEdit + liste + OK) → `Functions for Protection (N)` sayacı
- Fonksiyon özellikleri (sağ panel): **Virtualization / Mutation / Ultra**
  (QComboBox), `Complexity` (yüzde), Lock to license
- Alt: **`Compile`** düğmesi → `<hedef>.vmp.exe` üretimi

## 3. Test_64.exe — korunacak hedef (kullanıcının dosyası)

| Özellik | Değer |
|---|---|
| Dosya | `Test_64.exe` (12.800 bayt) — PE32+ x64, console subsystem |
| Derleyici | MSVC (UCRT: `api-ms-win-crt-*.dll` + `KERNEL32.dll` importları) |
| Korunacak sembol | `MovePlayer` (string tablosunda mevcut — VMProtect fonksiyon
  listesinde görünür) |
| GUI | yok (konsol) — VMProtect'in *protection hedefi*, Qt barındıran süreç
  VMProtect.exe'nin kendisidir |

## 4. V3.2 — SANDBOX'TA GERÇEK KOŞU (rootless Wine ile) — KANITLANDI

Önceki sürümlerde bu bölüm "sandbox Windows/GUI çalıştırmaz" diyordu. **Artık
yanlış**: rootless Wine 10 + Xvfb ile **gerçek VMProtect 3.9.4 sandbox içinde
koşuyor ve aracımız onu sürüyor.** Kurulum (tamamı root'suz):

```bash
# (1) Wine paketleri kullanıcı alanına (root gerekmez)
cd ~/vmprotect/wine_pkgs && apt-get download wine64 libwine wine
for f in *.deb; do dpkg -x "$f" ../wine_root/; done

# (2) wineserver yönlendirme betiği (mutlak /usr/lib/wine yollarını yeniden yaz)
cat > ../wine_root/usr/lib/wine/wineserver <<'EOF'
#!/bin/sh -e
exec /home/z/my-project/vmprotect/wine_root/usr/lib/wine/wineserver64 -p0 "$@"
EOF

# (3) LD_PRELOAD yol-shim'i: /usr/share/wine + /usr/lib/wine + zlib1.dll
#     (scripts/wineshim.c — open/stat/execve yeniden yönlendirme)
gcc -shared -fPIC -O2 -o ../wine_root/wineshim.so scripts/wineshim.c -ldl

# (4) zlib1.dll (Debian wine kalitalı user32.dll import ediyor!)
#     MSYS2: mingw-w64-ucrt-x86_64-zlib → ucrt64/bin/zlib1.dll
#     → wine_root/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ + prefix system32

# (5) Xvfb + prefix kurulumu
Xvfb :95 -screen 0 1600x1000x24 & sleep 2
export WINEPREFIX=~/vmprotect/wineprefix
export PATH="$WINE_ROOT/usr/lib/wine:$PATH"
export LD_PRELOAD=$WINE_ROOT/wineshim.so
export WINEDLLPATH="$WINE_ROOT/usr/lib/x86_64-linux-gnu/wine"
DISPLAY=:95 wine64 wineboot --init          # ~60sn

# (6) VMProtect 3.9.4'ü Test_64.exe ile başlat
cd ".../VMProtect Ultimate 3.94/"
DISPLAY=:95 wine64 VMProtect.exe Test_64.exe
```

### V3.2'de ölçülmüş gerçek sonuçlar (sandbox, wine):

| Ölçüm | Değer |
|---|---|
| statik-Qt tespiti | `memory-signature: Qt5 (static) — V307-3/V3.1` (V307-3 yaması taşındı) |
| canlı QObjects | **4.171** (boş açılış: 392) — Test_64.exe argümanıyla |
| canlı widget'lar | **391**; MainWindow **141** çocuk (QMenuBar/QStackedWidget/QToolButton...) |
| sınıf kaydı | **151** — MainWindow 82 slot TAM İSİMLE (addFunction, compile, treeItemDoubleClicked...) |
| qt_static_metacall ABI doğrulaması | `test edx,edx / mov rbx,rcx / cmp r8d,81 / mov rdi,r9` = MS x64 ✔ |
| MainWindow::addFunction() invoke | **DIALOG AÇILDI** — FunctionDialog+QLineEdit+QLabel bellekte |
| MainWindow::compile() invoke | **ProgressDialog+QProgressBar oluştu** (ptrace yolu) |
| XTEST F9 (derleme kısayolu) | **Test_64_MemoryProtection.vmp.exe = 6.631.323 bayt** üretildi |
| TOPLU üretim | **11/11 varyant** (bkz. sandbox_proof/ — GERÇEK çıktılar) |

### Neden iki invoke yolu?
- **ptrace + qt_static_metacall** (derin bellek çağrısı): fonksiyon dialogunu
  bellek seviyesinde AÇTI — kanıt: rescan'de `FunctionDialog`/`QLineEdit`
  `[YENI WIDGET]` olayları. Ama uzun işlemlerde wineserver pipe-read restart
  riski (V3.2'de fixSyscallRestart + gerçek-yığın çerçevesi + fırtına-abort
  ile süreç HAYATTA kalıyor).
- **XTEST giriş** (Tier-1 dengi): F9 kısayolu → Qt NATIVE çalışır → tam
  derleme + çıktı. Uzun işler için güvenli yol. Ajan komutu: `{"cmd":"xkey","keysym":"F9"}`.

## 5. Toplu üretim motoru (kullanıcının isim şemasıyla)

`tools/vmp_batch.sh` — her varyant: .vmp XML yazar (Options bitleri +
MovePlayer CompilationType + OutputFileName) → wine'da açar → ajanın
`xkey F9`'u → çıktıyı kaydeder. Üretilen GERÇEK dosyalar (sandbox_proof/):

| Varyant | Boyut |
|---|---|
| Test_64_MemoryProtection.vmp.exe | 14.336 |
| Test_64_ImportProtection.vmp.exe | 14.336 |
| Test_64_ResourceProtection.vmp.exe | 14.336 |
| Test_64_Antidebug.vmp.exe | 14.336 |
| Test_64_MemoryLimitation.vmp.exe | 14.336 |
| Test_64_ALL.vmp.exe | 14.336 |
| Test_64_MovePlayer_VIRTUALIZATION.vmp.exe | 2.530.304 (VM çalışma zamanı!) |
| Test_64_MovePlayer_MUTATION.vmp.exe | 14.336 |
| Test_64_MovePlayer_ULTRA.vmp.exe | **2.555.392** (VM+mutasyon) |
| Test_64_MovePlayer_ULTRA_ImportProtection.vmp.exe | 2.554.880 |
| Test_64_MovePlayer_ULTRA_ALL.vmp.exe | 2.539.008 |

Options bitleri (kaynak koddan, core/core.h): 0x8 CryptValues | 0x40 RunnerCRC
| 0x80 EncryptRegs | 0x100 Pack | 0x200 ImportProtection | 0x400 CheckDebugger
| 0x800 CheckVirtualMachine | 0x1000 MemoryProtection | 0x10000
ResourceProtection | 0x20000 CheckKernelDebugger | 0x40000 StripDebugInfo.
Fonksiyon tipi (CompilationType): 0=Virtualization, 1=Mutation, 2=Ultra.

## 6. Windows'ta gerçek koşu (kullanıcı makinesi)

```bat
cmake -B build -G "Visual Studio 17 2022" -A x64 && cmake --build build --config Release
build\Release\uqt_agent --name VMProtect --allow-shell --script examples\vmprotect_scenario.json
```

## 7. Sandbox doğrulama durumu (V3.2)

| Test | Sonuç |
|---|---|
| Qt 6.8.2 mock hedef (demo_qt6) | 69/69 PASS |
| Qt 5.15.15 mock hedef (demo_qt5) | 69/69 PASS (aynı pakette) |
| VMProtect-benzeri akış (mock senaryo) | 15/15 PASS (81/81 komut) |
| ptrace invoke (mmap + uzak çağrı) | doğrulandı + wine'da ABI kanıtı |
| **GERÇEK VMProtect 3.9.4 + wine** | **4171 QObject / 391 widget / 151 sınıf** |
| **MainWindow::addFunction() bellekte dialog açtırdı** | **KANIT** |
| **XTEST F9 → gerçek .vmp.exe derlemesi** | **11/11 varyant üretildi** |

## 8. V3.3 — Options sekmesinin KESİN envanteri + bit haritası (kontrollü bellek deneyi)

**Yöntem (SS/OCR YOK):** VMProtect'e Options=N içeren .vmp yükle → ajanla
`{"cmd":"objects","class":"Property"}` → BoolProperty değer baytını (gövde
+0x38) oku → bit ↔ özellik eşleşmesi = hangi bit hangi BoolProperty'yi 0→1
çeviriyor. Tablo tabanı: Options=0 (hepsi kapalı) vs tek bit / ALL-bits
(0x79FC8) karşılaştırması.

### Options ağacı — 24 özellik (CorePropertyManager; bellekten döküm)

| Grup | Özellik | Sınıf |
|---|---|---|
| Virtual Machine | Version / Instances / Complexity | Enum/Value/ValueProperty |
| File | Memory Protection, Import Protection, Resource Protection, Pack the Output File | BoolProperty |
| Detection | Debugger, Virtualization Tools | Enum/BoolProperty |
| Additional | Segments, Strip Debug Information, Strip Relocations, Shadow Stack Compatible (CET), Watermark, Lock To HWID | String/Bool/Watermark/StringProperty |
| Messages | Debugger Found, Virtualization Tools Found, File Corrupted, Serial Number Required, HWID Mismatched | StringProperty |
| Licensing Parameters | File Name, Activation Server, Key Pair Algorithm | StringProperty |
| (fonksiyon) | Compilation Type (None/Virtualization/Mutation/Ultra), Lock To Serial Number | CompilationType/BoolProperty |

### .vmp Options bit haritası — deneysel doğrulama durumu

| Bit | Özellik | Bellek kanıtı (BoolProperty +0x38) |
|---|---|---|
| 0x1000 | Memory Protection | **0→1 ÇEVRİLDİ** (ALLBits deneyi) |
| 0x200 | Import Protection | **0→1 ÇEVRİLDİ** |
| 0x100 | Pack the Output File | **0→1 ÇEVRİLDİ** |
| 0x10000 | Resource Protection | **0→1 ÇEVRİLDİ** |
| 0x8000 | Strip Relocations | **0→1 ÇEVRİLDİ** |
| 0x800 | Virtualization Tools Detection | **0→1 ÇEVRİLDİ** (eski adı 'MemoryLimitation' YANLIŞTI) |
| 0x400 | Debugger Detection (user-mode) | enum etki (adres gürültülü, derleme farkı kanıtı) |
| 0x20000 | Debugger Detection (kernel-mode) | enum etki |
| 0x8 / 0x40 / 0x80 | CryptValues / RunnerCRC / EncryptRegs (dahili) | GUI BoolProperty yok |
| 0x40000 | Strip Debug Info | GUI BoolProperty ÇEVİRMEDİ (derleme düzeyinde etkili) |
| ? | Shadow Stack Compatible (CET) | 0x80000/0x100000/0x200000/0x400000/0x800000/0x1000000/0x20000000 yoklandı → XML bit maskesinde DEĞİL |

### V4 toplu üretim matrisi (tools/vmp_batch_v4.sh)

- **Aile 1 (MovePlayer YOK)**: 12 bit-seçenek tek tek + ALL = 13 exe
- **Aile 2 (MovePlayer ULTRA kalıcı)**: aynı 12 + ALL = 13 exe
- **Aile 3**: VIRTUALIZATION/MUTATION/ULTRA (default complexity) = 3 exe
- Toplam: **29 gerçek .vmp.exe** (complexity 0/100 varyantları için ağaç-satır
  tıklama özelliği gerekiyor — Options ağacındaki Complexity ValueProperty
  .vmp XML'inde bilinen bir öznitelikle ayarlanamıyor; deneysel olarak yoklandı).
