# V307-3 Yaması — Statik-Qt Tespiti (Bellek İmza Fallback'i)

## Sorun (ilk denemede neden çalışmadı)

VMProtect.exe gibi **statik bağlanmış, self-protected** ikili dosyalarda **hiçbir
Qt DLL modülü yüklenmez** (Qt5Core.dll / libQt5Core.so yok — Qt çalışma zamanı
binary içine gömülü ve bölümleri paketlenmiş/şifreli). Aracın klasik tespit yolu
yalnızca **yüklü modül isimlerine** bakıyordu:

```
qt_scan.cpp: if (!core) return false;   // "Qt yok" → analiz durur → 0 form / 0 obje
```

Sonuç: V302'de Professional 3.9.6 canlı taraması **0 QObject / 0 form** döndürdü.

## Çözüm (bu yama)

Modül bulunamadığında analiz artık durdurulmuyor; **okunabilir bellek bölgeleri
Qt imzaları için taranıyor**:

| İmza | Biçim | Anlamı |
|---|---|---|
| `qt_meta_stringdata` | UTF-8 | moc motoru (metaobject string tablosu etiketi) |
| `QMainWindow` | UTF-8 | pencere sınıfı |
| `lsFile` | UTF-8 | VMProtect'ın kendi çeviri anahtarı |
| `File` / `Edit` / `View` | UTF-16LE | Qt menü metinleri (UI kanıtı) |

Motor imzası **ve** UI metni birlikte bulunursa → `Qt5 (static)` teşhisi ile
analiz devam eder (nesne taraması zaten `q_ptr` geri-bağ INVARIANT'ı ile
çalışır — DLL'e ihtiyaç duymaz). Hiçbiri bulunmazsa dürüst negatif: "Qt yok".

## Değişen dosyalar

| Dosya | Değişiklik |
|---|---|
| `UniversalMVPUIAlgorithm_QT/src/qt_scan.cpp` | `QtDetector::detect()` — modül yoksa bellek-imza fallback'i (ana yama) |
| `src/analyzer.cpp` | `Analyzer::detectQtVersion()` — aynı fallback (bu varyantta; + `<cstring>` include) |

## ÖLÇÜLMÜŞ SONUÇ (V307 canlı kanıt, wine altında 11 sürüm)

| Önce (V302) | Sonra (V307-3) |
|---|---|
| 0 QObject, 0 form, "Qt yok" | **tespit 11/11 sürüm**; QObject: 3.0.9=317, 3.8.1=293, 3.8.7=32, 3.9.4=30, 3.9.6=36, 3.4.0=27, 3.2.0=4, 3.10.4=3, 3.6.0=3; 3.3.1 (x86) koşamadı |

Sınıf kaydı kısmi kalır (metaobject verisi self-protect tarafından bellekte bile
şifreli — `metaobject=0x0`), menü metinleri RAM'de açık (CE-tarzı tarama: File×698).

## UPX hakkında (dokunulmadı)

UPX **kaldırılmadı** — kaldırılacak bir şey yok: eski sürümlerin `.UPX0/.UPX1`
bölüm adları **kamuflaj**. Kanıt: `upx -d` → `NotPackedException: not packed by
UPX`. Bölümler VMProtect'ın kendi paketleyicisinden geliyor; 3.6.0+ sürümlerde
bölüm adları zaten rastgele. Bu yama yalnızca **tespit mantığını** düzeltir,
hedef binary'lere dokunmaz.

## Derleme

```bash
# iç varyant (V307'de kullanılan):
cd UniversalMVPUIAlgorithm_QT
g++ -std=c++17 -O2 -Iinclude src/*.cpp cli/main.cpp -o umvpqt_cli -lcapstone

# dış varyant (önce layout DB üret):
g++ -std=c++17 -Iinclude -Isrc -Itools/gen_layout tools/gen_layout/gen_layout.cpp -o bin/gen_layout
./bin/gen_layout > src/qt_layout_db.h
g++ -std=c++17 -O2 -Iinclude -Isrc -Itools/gen_layout src/*.cpp cli/main.cpp -o umvpqt -lcapstone
```

Bağımlılık: `libcapstone` (Debian: `libcapstone-dev`). Her iki varyant da bu
yamayla derlenip çalıştırılarak doğrulandı (dürüst negatif: Qt'siz süreçte
"Qt bulunamadı", çökme yok).
