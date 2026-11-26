# PATCHES — UniversalMVPUIAlgorithm_QT v3 değişiklik günlüğü

## V307-3 taşıması (GitHub dalından v3'e)
GitHub kökündeki `src/qt_scan.cpp` statik-Qt tespit yaması (bellek-imza
fallback'i: `qt_meta_stringdata`/`QMainWindow`/`lsFile` UTF-8 + `File`/`Edit`/
`View` UTF-16) bu projeye taşındı. VMProtect.exe gibi **statik-Qt +
self-protected** hedeflerde "Qt yok → 0 form/0 obje" körüğü kalktı.

## V3.1 — statik-Qt era seçimi (metaobject revision oylaması)
- `probeStaticQtEra()`: bellekteki QMetaObject yapılarının `data[0]`
  (revision) değerleri oyulanır: 7=Qt5.0-5.11, 8=Qt5.12+, 9-12=Qt6.x.
- Yanlış era → yanlış layout DB → widget doğrulaması çöker (392 QObject
  içinde 3 widget vakası). Artık era bellekten okunuyor.

## V3.2 — wine hedef desteği + kararlılık
| Dosya | Değişiklik |
|---|---|
| `src/invoke_linux.cpp` | **win64_** çağrı kuralı (rcx/rdx/r8/r9); **fixSyscallRestart()** (wine pipe_read kesilme onarımı: rax=-512 → rip-=2 + rax=orig_rax); çağrı çerçevesi **gerçek thread yığınına** (wine SEH yığın-sınır kontrolü mmap scratch'i reddediyordu); **waitTarget** her turda süre denetimi (olay fırtınası sonsuz döngüsü = ajan takılması); **SIGSEGV fırtına-abort** (8+ hedef fault → kayıtlar onarılırmalı geri yüklenir, süreç yaşamaya devam eder) |
| `src/invoke_common.cpp` | **QtActor::callSlot()** — qt_static_metacall(\_o, InvokeMetaMethod, \_id, \_a) doğrudan çağrı (statik Qt'de export yok); QString argüman marshall'i (QLineEdit::setText gibi slotlar için) |
| `src/invoke_x11.cpp` | **YENİ** — XTEST giriş katmanı: dlopen(libX11+libXtst), XSetInputFocus, XTestFakeKey/Button/Motion. Windows SendMessage dengi. |
| `src/agent.cpp` | wine/PE modül tespiti → win64 ABI anahtarı; `call` komutunda export yoksa **slot fallback**; `setText` slot fallback'i; **formWidgetCache_** (formlar artık hedeflenebilir — MainWindow::addFunction "widget bulunamadi" körüğü düzeltildi); **xkey/xclick/xtype/xwindows** komutları |
| `include/umvpqt/*` | arayüz genişletmeleri (setWin64Convention, callSlot, X11Input) |
| `tools/vmp_batch.sh` | **YENİ** — .vmp XML + ajan xkey F9 ile toplu gerçek derleme motoru |

## ÖLÇÜLMÜŞ ETKİ
| Ölçüm | Önce | Sonra |
|---|---|---|
| statik-Qt widget (VMProtect 3.9.4, argümansız) | 3 | (argümansız modda UI inşası da az; argümanlı) |
| statik-Qt widget (Test_64.exe argümanlı) | — | **391** |
| canlı QObject | 394 (boş açılış) | **4171** (dosyalı) |
| sınıf kaydı | 31 | **151** (MainWindow 82 slot) |
| "button'a bas" (statik Qt) | imkansız | **qt_static_metacall + XTEST** (çift yol) |
| gerçek .vmp.exe üretimi | yok | **11/11 varyant** |

## V3.3 — tam nesne envanteri + kesin bit haritası

| Dosya | Değişiklik |
|---|---|
| `src/agent.cpp` | **YENİ "objects" komutu**: widget olmayan QObject örneklerinin (Property/Model/Manager) envanteri; sınıf filtresi + QString üye alanı çözümü (fields) + ham bayt dökümü (raw) |
| `include/umvpqt/agent.h` | cmdObjects bildirimi |
| `tools/vmp_batch_v4.sh` | **YENİ** — düzeltilmiş bit haritasıyla 29-varyant tam matris motoru (Aile 1/2/3) |
| `docs/VMPROTECT_PROFILE.md` §8 | Options sekmesi 24 özellik envanteri + deneysel bit doğrulama tablosu |
| `docs/AGENT.md` | objects komut referansı + VMProtect kanıtı |

**Kanıt (gerçek VMProtect 3.9.4, wine):** `objects` komutu 165 özellik nesnesi
döktü; kontrollü bit deneyleriyle 6 bit↔özellik eşleşmesi kesinleştirildi
(0x800'in eski 'MemoryLimitation' etiketi 'Virtualization Tools Detection'
olarak düzeltildi).
