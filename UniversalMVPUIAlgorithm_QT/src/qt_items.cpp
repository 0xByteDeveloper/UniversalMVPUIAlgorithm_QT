// UMVPQT GOD STATE — Combo / Item Reader implementation
// ============================================================================
//  QComboBox degerleri: QStandardItemModel -> root item -> satirlar -> sutun 0
//  Item metni values listesinde DisplayRole(0) QVariant'inda.
// ============================================================================
#include "umvpqt/qt_items.h"

namespace umvpqt {

// QStandardItem objesi: [vptr][QStandardItemPrivate* d]
static Addr itemD(IProcessReader& proc, Addr item) { return proc.readAddr(item + proc.ptrSize()); }

std::string ComboModelReader::variantString(Addr vaddr) {
    if (!vaddr) return {};
    if (L.qt6Layout) {
        // QVariant::Private { union data[24]; quintptr bits } — inline QString icin
        // data[0..23] = QString [d][ptr][size]
        // is_shared bit'i = bits&1 — kalabalik onlemek icin direkt inline dene
        // (QString Qt6'da inline depolanir: relocatable, 24B <= MaxInternalSize)
        Addr d = proc.readAddr(vaddr + 0);
        Addr ptr = proc.readAddr(vaddr + 8);
        uint64_t size = proc.readAddr(vaddr + 16);
        (void)d;
        if (ptr < 0x1000) return {};
        if (size > 4096 || (int64_t)size < 0) return {};
        std::vector<uint16_t> w((size_t)size);
        if (!proc.read(ptr, w.data(), (size_t)size * 2)) return {};
        if (!QtReader::plausibleUtf16(w.data(), (size_t)size)) return {};
        return QtReader::utf16ToUtf8(w.data(), (size_t)size);
    } else {
        // Qt5 QVariant: { Data data[8]; uint type:30 flags } — QString inline
        // QString = { QStringData *d } -> veri d + offset
        Addr sd = proc.readAddr(vaddr + 0);
        if (sd < 0x1000) return {};
        int32_t size = proc.readI32(sd + L.ad_size);
        if (size < 0 || size > 4096) return {};
        int64_t offset = (int64_t)proc.readAddr(sd + L.ad_offset);
        std::vector<uint16_t> w((size_t)size);
        if (!proc.read(sd + offset, w.data(), (size_t)size * 2)) return {};
        if (!QtReader::plausibleUtf16(w.data(), (size_t)size)) return {};
        return QtReader::utf16ToUtf8(w.data(), (size_t)size);
    }
}

std::string ComboModelReader::itemText(Addr itemAddr) {
    Addr d = itemD(proc, itemAddr);
    if (!d) return {};
    // values: QList<QStandardItemData>
    if (!L.listUsesHeader) {
        Addr ptr = proc.readAddr(d + L.si_values + 8);
        uint64_t size = proc.readAddr(d + L.si_values + 16);
        if (!ptr || size > 256) return {};
        unsigned stride = L.sid_value + L.sz_QVariant;
        if (stride % 8) stride += 8 - (stride % 8);   // hizalama (QStandardItemData sizeof)
        for (uint64_t i = 0; i < size; i++) {
            Addr e = ptr + (Addr)(i * stride);
            int32_t role = proc.readI32(e);
            if (role == 0 || role == 1) {   // DisplayRole / EditRole
                std::string s = variantString(e + 8);
                if (!s.empty()) return s;
            }
        }
    } else {
        // Qt5: values = QVector<QStandardItemData> — QArrayData duzeni:
        // {ref(4), size(4), alloc(4), pad(4), offset(8@16)}; kayitlar q+offset + i*24
        Addr q = proc.readAddr(d + L.si_values);
        if (!q || q < 0x1000) return {};
        int32_t size = proc.readI32(q + 4);
        int64_t offset = (int64_t)proc.readAddr(q + 16);
        if (size < 0 || size > 256 || offset < 0 || offset > 0x100000) return {};
        unsigned entrySz = L.sid_value + L.sz_QVariant;
        if (entrySz % 8) entrySz += 8 - (entrySz % 8);
        Addr arr = q + (Addr)offset;
        for (int i = 0; i < size; i++) {
            Addr e = arr + (Addr)(i * entrySz);
            int32_t role = proc.readI32(e);
            if (role == 0 || role == 1) {
                std::string s = variantString(e + 8);
                if (!s.empty()) return s;
            }
        }
        return {};
    }
}

int ComboModelReader::modelRowCount(Addr modelAddr) {
    // model: QObject -> d -> QStandardItemModelPrivate::root (QScopedPointer<QStandardItem>)
    Addr d = proc.readAddr(modelAddr + proc.ptrSize());
    if (!d) return -1;
    Addr root = proc.readAddr(d + L.sim_root);
    if (!root || root < 0x1000) return -1;
    Addr rd = itemD(proc, root);
    if (!rd) return -1;
    auto kids = reader.readListAddrs(rd + L.si_children);
    return (int)kids.size();
}

bool ComboModelReader::persistentIndex(Addr pmiAddr, int& row, int& col) {
    Addr d = proc.readAddr(pmiAddr + L.pmi_d);
    if (!d || d < 0x1000) return false;
    // QPersistentModelIndexData { QAtomicInt ref; ... QModelIndex index; ...}
    // index alani: ref(4) + pad + QPersistentModelIndexData kendi duzeni...
    // pratik: d + 8'den itibaren QModelIndex { r, c, i, m } tara
    for (unsigned off = 0; off <= 64; off += 4) {
        int32_t r = proc.readI32(d + off);
        int32_t c = proc.readI32(d + off + 4);
        if (r >= 0 && r < 100000 && c >= 0 && c < 256) {
            Addr m = proc.readAddr(d + off + 16);
            if (m > 0x10000) { row = r; col = c; return true; }
        }
    }
    return false;
}

bool ComboModelReader::readCombo(Addr comboAddr, std::vector<std::string>& items,
                                  int& currentIndex, std::string& currentText) {
    items.clear();
    currentIndex = -1;
    currentText.clear();
    Addr d = proc.readAddr(comboAddr + proc.ptrSize());
    if (!d) return false;

    // ---- currentText (Qt6 dogrudan; Qt5 currentIndex'ten uretilir) ----
    if (L.cb_hasCurrentText && L.cb_currentText != 0xFFFFFFFFu) {
        auto s = reader.readQString(d + L.cb_currentText);
        currentText = s.utf8;
    }
    // ---- currentIndex (QPersistentModelIndex) ----
    int row = -1, col = -1;
    if (persistentIndex(d + L.cb_currentIndex, row, col)) currentIndex = row;

    // ---- model -> QStandardItemModel? ----
    Addr model = proc.readAddr(d + L.cb_model);
    if (!model || model < 0x10000) {
        // model yoksa currentText yeterli
        return !currentText.empty();
    }
    Addr md = proc.readAddr(model + proc.ptrSize());
    if (!md) return false;
    Addr root = proc.readAddr(md + L.sim_root);
    if (!root || root < 0x1000) return false;
    Addr rd = itemD(proc, root);
    // QStandardItem cocuklari DUZ listedir: childIndex(r,c) = r*columnCount + c
    // (satir sarmalayicisi YOK) — root children = [r0c0, r0c1, ...]
    auto kids = reader.readListAddrs(rd + L.si_children);
    int colCount = (int)proc.readI32(rd + L.si_columns);
    if (colCount <= 0) colCount = 1;
    if (colCount > 64) colCount = 1;
    for (Addr item : kids) {
        if (!item || item < 0x1000) { items.push_back("?"); continue; }
        std::string t = itemText(item);
        items.push_back(t.empty() ? "?" : t);
    }
    (void)colCount;   // cok-sutun modellerde sutun 0 secilir; kids zaten sirali
    if (currentText.empty() && currentIndex >= 0 &&
        (size_t)currentIndex < items.size()) currentText = items[currentIndex];
    return !items.empty();
}

} // namespace umvpqt
