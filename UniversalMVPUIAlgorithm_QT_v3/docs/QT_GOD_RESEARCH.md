# QT GOD RESEARCH — SDK İç Mimarisine Askeri Düzey Dalış

> Bu doküman `UniversalMVPUIAlgorithm_QT`'nin inşası sırasında yapılan **derin Qt SDK
> araştırmasının** kaydıdır. Tüm bilgiler ya Qt private header'larının offsetof-probe
> ile ölçülmesinden (Qt 5.15.15 + Qt 6.8.2, `tools/gen_layout`), ya da moc 5.15/6.8'in
> gerçek çıktılarının incelenmesinden ya da canlı süreç belleğinin ampirik doğrulanmasından
> gelir. Kaynak kod kopyası okunmadı; her şey **bellekte ölçüldü**.

## 1. Nesne Düzenleri (64-bit)

### QObject (her iki çağ)
```
[+0x00] vtable işaretçisi
[+0x08] d_ptr (QObjectData türevi → QWidgetPrivate vb.)
INVARIANT: *(d + 0x08) == q   (q_ptr geri-bağı — GOD tarama anahtarı)
```

### QObjectData
| Alan | Qt 5.15 | Qt 6.8 | Not |
|---|---|---|---|
| q_ptr | 8 | 8 | her çağ sabit |
| parent | 16 | 16 | |
| children (QList) | 24 | 24 | Qt5: 8B, Qt6: 24B (d,ptr,size) |
| flags bitfield | 32 | 48 | **isWidget=bit0, wasDeleted=bit2, isWindow=bit6** |
| postedEvents | 36 | 52 | |
| metaObject (dinamik) | 40 | 56 | null → static metaobject kullanılıyor |
| (Qt6 ekstra) | | bindingStorage | |

Qt 6.0–6.7'de parent/children QObjectPrivate içindedir (6.8'de QObjectData'ya taşındı) —
runtime kalibrasyon bu farkı kapatır.

### QObjectPrivate (Qt 6.8)
```
extraData(+0x48)  threadData(+0x50)  connections(+0x58)  declarativeData(+0x60)  sharedRefcount(+0x68)
```
Qt 5.15 aynı sıra, QObjectData kısa olduğu için +0x30'dan başlar. **connections →
ConnectionData → SignalVector → ConnectionList[i] → Connection** zinciri signal-slot
event tespitinin kalbidir (aşağıda).

### QString
- **Qt 6**: `QArrayDataPointer { d; ptr(char16_t*); size }` = 24B → **[d][ptr][size]**,
  UTF-16 verisi ptr'de.
- **Qt 5**: tek işaretçi `QStringData(QArrayData) { ref(4); size(4); alloc(4); pad(4);
  offset(8@16) }` → veri `d + offset`'te, boyut `d+4`'te.

### QList / QVector (Qt5'in iki yüzü — ampirik bulgu!)
- **Qt 6**: `[d][ptr][size]` (QArrayDataPointer), elemanlar ptr'de.
- **Qt 5**: **İKİ format birden tespit edildi**:
  - QWidget children (`QList<QObject*>`): `{ref, alloc, begin, end, array@16}`
    (QListData düzeni — boyut = end-begin).
  - QStandardItem children/values (`QVector`): `{ref, size@4, alloc, pad, offset@16}`
    (QArrayData düzeni — veri q+offset'te).
  - UMVPQT **çift-hipotez çözümleyici** kullanır: her iki formül denenir, geçerli
    işaretçiler + geri-bağ invariant'larını üreten kazanır.

### QWidget / QWidgetData
```
QWidget objesi: [QObject vptr][d_ptr][QPaintDevice vptr][devFlags,painters]
QWidgetPrivate::data → QWidgetData {
  winid(+0)  widget_attributes(+8)  window_flags(+12)  bitfield(+16)
  crect(+24: 4 int x1,y1,x2,y2)  pal(+40)  fnt(+48)  wrect(+56)
}
görünürlük: widget_attributes & (1 << WA_WState_Visible=15)   (her iki çağ!)
windowTitle: extra → QWExtra.topextra → QTLWExtra.caption (QString)
```

### QMetaObject (bellekteki staticMetaObject)
```
[+0] superdata (SuperData = inline tek işaretçi, doğrudan ata metaobject'i)
[+8] stringdata    Qt6: uint* (offset,length çiftleri)  Qt5: QByteArrayData* tablo
[+16] data         uint[]: 14-int başlık + metotlar + property'ler
[+24] static_metacall (fn ptr)
[+32] relatedMetaObjects  [+40 Qt6: metaTypes]  [+48/40] extradata
```
**data başlığı (14 int, her çağ aynı)**: `revision, className, classInfoCount,
classInfoData, methodCount, methodData, propertyCount, propertyData, enumeratorCount,
enumeratorData, constructorCount, constructorData, flags, signalCount`

**Revision çağ haritası**: 7=Qt5.0–5.11, 8=Qt5.12+, 9=Qt6.0, 10=Qt6.2, 11=Qt6.5,
12=Qt6.6+ (moc 6.8 ampirik çıktısı: `12`).

**Metot kayıtları**: Qt6 6-int (name, argc, parameters, tag, flags, metaTypeOffset),
Qt5 5-int (metaTypeOffset yok). Property: Qt6 5-int, Qt5 3-int + ayrı notify dizisi.

**stringdata çözümü (moc çıktılarından ampirik)**:
- Qt 6.8: `stringdata[2i] = bayt ofseti, stringdata[2i+1] = uzunluk`, metin
  `(char*)stringdata + ofset`. (QtMocHelpers::stringData → offsetsAndSizes.)
- Qt 6.0–6.7: aynı (codebrowser doğrulaması).
- Qt 5: 24-byte QByteArrayData başlıkları: metin `başlık + header.offset`.
- Qt 4: char* blob (data dizisindeki ofsetlerle).

### Signal-Slot: Connection yürüyüşü (qobject_p_p.h, Qt 6.8; Qt 5.15'te de benzer)
```
QObjectPrivate::connections → ConnectionData {
  currentConnectionId(4) ref(4) signalVector(8) senders(8) currentSender(8) orphaned(8)
}
SignalVector { next/base(8) allocated(8) ConnectionList[]: {first,last} × (N+1) }
  → sinyal i'nin listesi SignalVector + 0x10 + i*16'ta
Connection {
  next(8) prev(8) nextConnectionList(8) prevConnectionList(8) sender(8) receiver(8)
  receiverThreadData(8) callFunction|slotObj(8) argumentTypes(8) ref(4) id(4)
  method_offset(2) method_relative(2) bits(4)
}
bits: signal_index:27 | connectionType:2(3 Qt5) | isSlotObject:1(30 Qt5 / 29 Qt6) | ...
```
- `signal_index` **GLOBAL** sinyal indeksidir: **taban sınıftan türemişe doğru**
  sayılır (QObject'ün sinyalleri 0'dan başlar!). Zincir çözümlemesi tersten yürütülür.
- `method_offset + method_relative` = receiver'ın **global metot indeksi** →
  zincir üzerinde ilgili sınıf + slot adı çözülür.
- PMF bağlantıları `isSlotObject=1`: slot `QPrivateSlotObject` içindeki
  pointer-to-member'dan okunur: `*(slotObj + 16)` = slot fonksiyonunun **gerçek kod
  adresi** (Itanium non-virtual PMF = {funcptr, adj}).
- Qt5'te isSlotObject bit'i **bit 30**'da (connType 3-bit olduğu için), Qt6'da bit 29'da.

### QComboBox / QStandardItemModel (ampirik)
```
QComboBoxPrivate: model(+440 Qt5/+? Qt6) lineEdit container currentIndex
(QPersistentModelIndex) root placeholderText currentText(Qt6)
QStandardItemModelPrivate: root(+152 Qt5 / +272 Qt6) → görünmez QStandardItem
QStandardItem: [vptr][d→QStandardItemPrivate]  d+40 = q_ptr (geri-bağ!)
QStandardItemPrivate: model(0) parent(8) values(16) children(24) rows(32) columns(36)
values: QStandardItemData { int role; pad; QVariant value } kayıtları
QVariant: Qt6 {data[24] inline + bits} — QString 24B satır içi; Qt5 {data[8] + type/flags}
```
QStandardItem çocukları **düz** listedir: `childIndex(r,c) = r*columnCount + c`
(satır sarmalayıcısı yoktur!). Item metni values içindeki DisplayRole(0)/EditRole(1)
kayıdındaki QVariant'tan okunur.

## 2. Kod-Tarafı Keşifler (disassembly)

### qVersion() — tam sürüm tespiti
```
[endbr64] lea rax,[rip+disp]; ret   (veya mov rax,[rip+disp]; ret)
→ disp çözülür → statik "6.8.2" stringi okunur
```
endbr64 (CET) öneki mutlaka atlanmalı (Debian Qt5 build'lerinde var).

### metaObject() thunk'u (moc 6.x override)
```
mov rax,[rdi+8]; mov rax,[rax+56]; test rax,rax; cmove/branch
lea rax,[rip+X]; ret          ← &staticMetaObject (DAL LI kod!)
```
Basit desen eşleşmesi yetmez → **capstone ile rip-göreli tüm hedefler taranır**,
`quickLooksLikeMo` (data[0] revision 4..20 + className indeksi makul) testini geçen
hedef metaobject kabul edilir.

### qt_static_metacall switch çözümü (GOD: metod → kod adresi)
-O0 çıktısı (gerçek demodan):
```
cmp [rbp-0x1c], 0        ; _c == InvokeMetaMethod
cmp [rbp-0x20], 2        ; id >= methodCount? (aralık kontrolü — yanlış yorumlanmamalı!)
cmp [rbp-0x20], 0; je case0
cmp [rbp-0x20], 1; je case1
case0: ... call _slot0
case1: ... call _slot1
```
Çözümleyici: **geçiş 1** — `cmp id,N` + `je hedef` çiftlerinden case gövde haritası;
**geçiş 2** — her gövdedeki ilk `call`'ın rel32 hedefi = slot fonksiyonu. Fonksiyon
sonu = ilk `ret` (tek epilog).

### QWidget vtable override analizi
`QWidget::paintEvent` sembol adresi (`_ZN7QWidget10paintEventEP11QPaintEvent`) bellekteki
QWidget vtable'ında aranır → **slot indeksi ampirik bulunur** (sabit liste KOD YOK!).
Nesnenin vtable'ında aynı indeks farklıysa = override → handler adresi + disasm.

## 3. Sembol Çözümü

| Hedef | Kaynak |
|---|---|
| Linux .so/.exe | diskteki ELF `.dynsym` (+ `.symtab` varsa — exe'lerde tam fonksiyon sınırları!) |
| Windows DLL | bellekteki PE export tablosu |
| vtable for X | `_ZTV<len><X>` / `??_7X@@6B@` (+0x10 Itanium / +0x8 MSVC) |
| staticMetaObject | `_ZN<len>X16staticMetaObjectE` / `?staticMetaObject@...` |
| RTTI | Itanium: `vtable[-1] → typeinfo { vptr, name* }` → "N12MyWidgetE" demangle |
| ana exe | Linux: `/proc/pid/exe` hedefi; class RTTI + metacall thunk'larıyla çözülür |

## 4. Sürüm Bağımsızlığı Stratejisi

1. **Gömülü DB'ler** (5.15.15 + 6.8.2) — offsetof-probe ile üretildi.
2. **32-bit rescale**: genişlik-imzalı alan sınıfları (P/I/S) ile 64-bit tablodan
   türetme (testler 64-bit; 32-bit hedef bellek okuma aynı invariant'larla çalışır).
3. **Runtime kalibrasyon**: q_ptr geri-bağı + çocuk-listesi (d,ptr,size)/(begin,end)
   desenleri + QWidgetData imza taraması → bilinmeyen sürümlerde alan konumları.
4. **Ampirik çözümleyiciler**: çift-format QList, LEA/MOV/endbr thunk desenleri,
   `quickLooksLikeMo` doğrulaması — yanlış pozitifleri süzerek çalışır.

## 5. Doğrulama Ortamı

- Qt 6.8.2 + Qt 5.15.15 toolchain'leri rootless deb-extraction ile kuruldu
  (`/home/z/my-project/toolchain`); test hedefi `QT_QPA_PLATFORM=offscreen` ile koştu.
- `tests/run_integration.sh`: 69 test — iki çağda da formlar/widget'lar/özellikler/
  combobox/event'ler/handler adresleri/asm dump/JSON/monitor doğrulandı.
