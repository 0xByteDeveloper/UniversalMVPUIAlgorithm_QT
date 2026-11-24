# UMVPQT — GOD STATE Algoritma Akışı

```
[1] SÜREÇ AÇILIŞI
    /proc/pid/maps (Linux) | Toolhelp32 (Win)
    modül tablosu: path-birleşimli bölgeler → Module { base, end, symbols }
    semboller: diskteki ELF .dynsym + .symtab | bellekteki PE export tablosu
    ana exe tespiti: /proc/pid/exe hedefi

[2] QT TESPİTİ
    modül isimleri (Qt5Core/Qt6Core/QtCore.dll...) → çağ
    qVersion() disassembly (endbr64|lea|mov rax,[rip+disp]; ret) → TAM SÜRÜM
    fallback: rodata "N.N.N" taraması (major 4/5/6 filtresiyle)
    metaobject revision → 7/8=Qt5, 9..12=Qt6

[3] LAYOUT ÇÖZÜMÜ
    gömülü DB (5.15.15 | 6.8.8) → QtLayouts
    + 32-bit rescale (ptr genişliği 4) + kalibrasyon kancaları

[4] INSTANCE TARAMASI (GOD)
    (a) vtable-anchored: bilinen _ZTV* vtable değerleri heap blob'larında aranır
    (b) invariant: her 8-hizalı X için *(X+P)=D, *(D+P)=X (q_ptr geri-bağı)
    (c) birleşim + dedup → QObject adres listesi

[5] SINIF ÇÖZÜMÜ (ClassRegistry, cache'li)
    vtable → 1) modül sembolü _ZTV7X        → sınıf + staticMetaObject
             2) vtable[0] thunk → capstone rip-taraması → QMetaObject
             3) RTTI typeinfo → gerçek app sınıf adı
    QMetaObject parse → metodlar/sinyaller/slotlar/property'ler/zincir

[6] WIDGET AĞACI
    isWidgetClass (zincirde QWidget) + wasDeleted süzgeci
    parent/children → formlar (top-level) + derinlikli ağaç
    özellikler: crect/geometry, WA_WState_Visible, objectName, windowTitle,
    buton text (QAbstractButtonPrivate), label text, lineEdit (QWidgetLineControl)

[7] EVENT ANALİZİ
    her nesne: connections → ConnectionData → SignalVector[1..N]
      → Connection{sender, receiver, signal_index, method_offset+relative, isSlotObject}
    global sinyal/metot indeksi → zincir üzerinde TERSTEN yürüyerek AD çözümü
    PMF: slotObj+16 → slot kod adresi → metacall haritasıyla isimleştirme

[8] HANDLER KOD ÇÖZÜMÜ
    qt_static_metacall disasm: cmp/je case haritası → case gövdesindeki ilk call
      = slot fonksiyon adresi (metod index → adres tablosu)
    fonksiyon sınırı: sonraki sembol | ilk ret
    VirtualSlotMap: QWidget::paintEvent vb. sembolden vtable indeksi (ampirik)
      → nesne vtable'ı farklıysa override → handler + .asm dump

[9] COMBOBOX MODEL YÜRÜYÜŞÜ
    QComboBoxPrivate.model → QStandardItemModelPrivate.root → düz çocuk listesi
    (childIndex = r*colCount+c) → values → DisplayRole QVariant → QString
    currentIndex (QPersistentModelIndex) + currentText

[10] RAPOR
    konsol ağacı + JSON + .asm dosyaları

[11] MONITOR (opsiyonel)
    yeniden tarama → adres bazlı diff:
    [YENI FORM] [KAPANAN FORM] [YENI WIDGET] [METIN DEGISIMI] [COMBO SECIMI] [GORUNURLUK]
```

Her adım salt **harici bellek okuma** (ReadProcessMemory / process_vm_readv) + disassembly
ile çalışır — hedef sürece KOD ENJEKSİYONU YOKTUR, PDB gerekmez.
