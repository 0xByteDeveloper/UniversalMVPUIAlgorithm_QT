# UQT_AGENT — Yapay Zeka Surucu Protokolu (AI Agent Interface)

`uqt_agent`, UMVPQT SDK'yi bir **yapay zekanin bir uzvu gibi** kullanmasi
icin tasarlanmis stateful JSON-lines komut motorudur: her satir bir komut,
her cikti tek satir JSON. Ekran goruntusu / OCR YOK — her sey harici bellek
cozumlemesiyle.

## Oturum modlari

```bash
# 1) interaktif REPL (stdin/stdout JSON-lines)
uqt_agent --pid 1234
uqt_agent --name VMProtect --allow-shell

# 2) script dosyasi (tek atis + tum yanitlar JSON-lines)
uqt_agent --pid 1234 --script examples/vmprotect_scenario.json --allow-shell

# 3) surec listesi
uqt_agent --list
```

## Komut referansi

### Oturum
| Komut | Alanlar | Aciklama |
|---|---|---|
| `attach` | `pid` veya `name` | surece baglan |
| `analyze` | — | tam tarama (formlar, objeler, event'ler, handler'lar) |
| `info` | — | Qt surumu, nesne/form/baglanti sayilari |
| `quit` | — | oturumu kapat (invoker temiz ayrilir) |

### Kesif (salt okunur)
| Komut | Alanlar | Aciklama |
|---|---|---|
| `forms` | `deep` | tum formlar; `deep=true` → widget listesiyle |
| `tree` | `form:idx` | bir formun tum widget agaci + ozellikler |
| `find` | `class`, `text`, `name` | eslesen widget'lar (buyuk/kucuk duyarsiz) |
| `props` | `addr`/`name`/`text` | tek widget detayi (baglantilar dahil) |
| `handlers` | `addr`/`name`/`text` | event handler'lari + base–end adres araliklari + modul |
| `rescan` | — | yeniden tara + onceki raporla DIFF (olay listesi) |

### AKSIYON (invoke — uzaktan cagri)
| Komut | Alanlar | Aciklama |
|---|---|---|
| `click` | `addr`/`name`/`text`, `timeout` | dugme tikla (`QAbstractButton::click`) |
| `check` | `... , value:bool` | checkbox isaretle/kaldir (`setChecked`) |
| `setcombo` | `... , value` veya `index` | combobox degeri sec (`setCurrentIndex`) |
| `settext` | `... , value` | metin yaz (`QLineEdit::setText` — QString hedefte kurulur) |
| `selectrow` | `... , row` | listeden satir sec (`QListWidget::setCurrentRow`) |
| `call` | `addr`, `fn`, `a1/index/value/row` | dogrudan `Class::method` cagrisi |
| `sh` | `run` | shell komutu (yalniz `--allow-shell` ile — dosya tasi/yeniden adlandir) |

### Bekleme / senkronizasyon
| Komut | Alanlar | Aciklama |
|---|---|---|
| `wait` | `ms` | bekle (hedef serbest calisir) |
| `waitform` | `title`, `timeout` | yeni form acilmasini bekle (modal diyalog!) |
| `waitwidget` | `text`/`name`, `timeout` | yeni widget olusmasini bekle |
| `script` | `file` | baska bir script dizini ayni oturumda calistir |

Widget secimi: her aksiyon komutu `addr` VEYA `name` VEYA `text` ile hedefi
bulur; bulunamazsa otomatik bir `rescan` yapilir (dinamik yeni objeler).

## MODAL diyalog akisi (kritik desen)

`click` komutu, handler'i `QDialog::exec()` acan dugmelerde **pending**
doner (cagri calisiyor, GUI serbest). Ayni anda:

```json
{"cmd":"click","name":"btnAddFunction","timeout":1500}   → pending (modal acildi)
{"cmd":"waitform","title":"Add function","timeout":15000} → form bilgisini dondurur
{"cmd":"settext","name":"editSearch","value":"MovePlayer"}
{"cmd":"selectrow","name":"listDialog","row":3}
{"cmd":"click","name":"btnOK","timeout":6000}             → diyalog kapanir,
                                                            pending dis cagri tamamlanir
```

Linux ptrace motoru bu ici-cagrilari AynI GUI thread'i uzerinde, ayri
64KB yigin bolgeleriyle enjekte eder — Qt thread-affinity korunur.
Windows motoru CreateRemoteThread + RWX stub kullanir (64-bit hedef).

## Yanit formati

```json
{"seq":7,"cmd":"click","ok":true,"data":{"action":"click","target":"0x55..","invoked":true,"pending":false,"ret":"0x0"}}
{"seq":8,"cmd":"click","ok":false,"err":"widget bulunamadi"}
```

`pending:true` = hata DEGIL: cagri hedefte hala calisiyor (modal).

## VMProtect senaryosu (kullanicinin gercek is akisi)

`examples/vmprotect_scenario.json` — kullanicinin tanimladigi TAM akis:
Options → Memory protection YES → derle → `Test_64_MemoryProtection.vmp.exe`
... tekli ozellikler, ALL, `MovePlayer` ekleme (ULTRA/MUTATION/VIRTUALIZATION)
+ `Test_64_MovePlayer_ULTRA.vmp.exe` ... 11 cikti + ayar yanitlari
dogrulanmis olarak uretilir (sandbox'ta mock hedefle 15/15 PASS).

Windows'ta gercek VMProtect 3.9.4'e ayni script:
```bash
uqt_agent --name VMProtect --allow-shell --script examples/vmprotect_scenario.json
```
(`sh` komutlarindaki `VMP_OUT` dizini ve mv hedef adlarini gercek cikti
dizinine uyarlayin; docs/VMPROTECT_PROFILE.md — hedef profili.)


## V3.2 — Yeni komutlar (wine hedefleri için X11 giriş katmanı)

| Komut | Anlamı |
|---|---|
| `{"cmd":"xkey","keysym":"F9"}` | XTEST klavye (kısayol tetikler — VMProtect'te F9=derleme). `Ctrl+F9` tarzı kombinasyon destekli |
| `{"cmd":"xclick","x":..,"y":..}` | XTEST tıklama (mutlak ekran koordinatı) |
| `{"cmd":"xtype","text":"MovePlayer"}` | XTEST tuş dizisi (odak: en büyük pencere otomatik) |
| `{"cmd":"xwindows"}` | X pencere envanteri (en büyük pencere kimliği) |

## V3.2 — "call" komutunun statik-Qt fallback'i

Export tablosu olmayan hedeflerde (VMProtect gibi statik Qt) `{"cmd":"call",
"fn":"MainWindow::addFunction"}` şöyle çözülür:
1. export aranır → yok
2. **qt_static_metacall(_o, InvokeMetaMethod, _id, _a)** doğrudan çağrılır
   (sınıf kaydından metacall adresi + slot indeksi bellekten okunur)
3. tek-QString argümanlı slotlar `value` alanıyla marshall edilir

ÖRNEK KANIT (gerçek VMProtect 3.9.4, sandbox/wine):
```
{"cmd":"call","address":"0x7ffffe82f1d0","fn":"MainWindow::addFunction"}
  → rescan: [YENI WIDGET] FunctionDialog, QLineEdit, QLabel
```

## V3.3 — "objects" komutu (widget OLMAYAN nesneler dahil tam envanter)

`tree`/`props` yalnızca widget ağacını döker. Bir Qt uygulamasının veri modeli
(widget olmayan QObject'ler: Property, Model, Manager sınıfları) `objects`
ile envanterlenir:

```json
{"cmd":"objects","class":"Property","fields":true,"raw":64,"limit":400}
```

| Parametre | Anlam |
|---|---|
| `class` | sınıf adı alt-dizi filtresi (boş = tüm QObject örnekleri) |
| `fields` | nesne gövdesindeki **QString üye alanlarını** çözer (ad/değer metinleri) |
| `raw` | N bayta kadar ham hex dökümü ekler (değer ofset keşfi) |

Çıktı: `{count, objects:[{address, class, objectName, fields:[{off,value}],
raw}]}` — bellek taraması, SS/OCR YOK.

**KANIT (gerçek VMProtect 3.9.4, wine):** `{"cmd":"objects","class":"Property"}`
→ 165 nesne; Options sekmesinin TAM ağacı bellekten: `BoolProperty("Memory
Protection")`, `BoolProperty("Import Protection")`, `BoolProperty("Resource
Protection")`, `BoolProperty("Pack the Output File")`, `EnumProperty("Debugger")`,
`BoolProperty("Virtualization Tools")`, `StringProperty("Segments")`,
`BoolProperty("Strip Debug Information")`, `BoolProperty("Strip Relocations...")`,
`BoolProperty("Shadow Stack Compatible")`, `WatermarkProperty("Watermark")`,
`StringProperty("Lock To HWID")`, mesaj özellikleri (Debugger Found / VM Tools
Found / File Corrupted / Serial Number Required / HWID Mismatched),
`ValueProperty("Complexity")`, `ValueProperty("Instances")`,
`EnumProperty("Version")`, `CompilationTypeProperty("Compilation Type")`,
`BoolProperty("Lock To Serial Number")`, lisans/lisanslama özellikleri...
— hepsi adı + yardım metniyle (fields) bellekten okundu.
