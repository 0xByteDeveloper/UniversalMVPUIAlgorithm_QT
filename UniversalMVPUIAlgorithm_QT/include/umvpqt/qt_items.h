// UMVPQT GOD STATE — ComboBox / Item Model Reader
// ============================================================================
//  QComboBoxPrivate: model, lineEdit, currentIndex(QPersistentModelIndex),
//  currentText(QString). QStandardItemModel: invisible root QStandardItem
//  -> cocuklar satir, satirlarin cocuklari sutun. Item metni:
//  QStandardItemPrivate::values = QList<QStandardItemData { int role; QVariant }>
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include "qt_layouts.h"
#include "qt_strings.h"
#include "qt_metaobject.h"
#include "qt_scan.h"

namespace umvpqt {

struct ComboModelReader {
    IProcessReader& proc;
    const QtLayouts& L;
    ClassRegistry& reg;
    QtReader& reader;

    ComboModelReader(IProcessReader& p, const QtLayouts& l, ClassRegistry& r, QtReader& rd)
        : proc(p), L(l), reg(r), reader(rd) {}

    // QComboBox instance -> {items, currentIndex, currentText}
    bool readCombo(Addr comboAddr, std::vector<std::string>& items,
                   int& currentIndex, std::string& currentText);

    // QVariant icinden QString (her iki cag)
    std::string variantString(Addr vaddr);

    // QStandardItem -> text (values listesinde DisplayRole)
    std::string itemText(Addr itemAddr);

    // QStandardItemModel satir sayisi (root->children)
    int modelRowCount(Addr modelAddr);

    // QPersistentModelIndex d-ptr -> QModelIndex {r,c}
    bool persistentIndex(Addr pmiAddr, int& row, int& col);
};

} // namespace umvpqt
