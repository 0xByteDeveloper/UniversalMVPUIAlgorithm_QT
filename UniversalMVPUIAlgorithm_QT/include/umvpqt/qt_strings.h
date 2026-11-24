// UMVPQT GOD STATE — Qt String / Container readers
// ============================================================================
//  Qt6 QString = [d][ptr(char16_t*)][size]  (24B, 64-bit)
//  Qt5 QString = [d] -> QStringData{ref,size,alloc,offset} + offset
//  Qt6 QList   = [d][ptr][size]  (elemanlar ptr'de)
//  Qt5 QList   = [d] -> QListData::Data{ref,size,alloc,offset}, elemanlar d+offset
// ============================================================================
#pragma once
#include "types.h"
#include "process.h"
#include "qt_layouts.h"
#include <string>
#include <vector>

namespace umvpqt {

struct QtReader {
    IProcessReader& proc;
    const QtLayouts& L;

    QtReader(IProcessReader& p, const QtLayouts& lay) : proc(p), L(lay) {}

    // ---- UTF-16 -> UTF8 (guvenli, bosa harcamasiz) ----
    static std::string utf16ToUtf8(const uint16_t* w, size_t n) {
        std::string out;
        out.reserve(n);
        for (size_t i = 0; i < n; i++) {
            uint16_t c = w[i];
            if (c == 0) { out += '?'; continue; }
            if (c >= 0xD800 && c <= 0xDBFF && i + 1 < n) {
                uint16_t c2 = w[i + 1];
                if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
                    uint32_t cp = 0x10000 + (((uint32_t)c - 0xD800) << 10) + (c2 - 0xDC00);
                    i++;
                    out += (char)(0xF0 | (cp >> 18));
                    out += (char)(0x80 | ((cp >> 12) & 0x3F));
                    out += (char)(0x80 | ((cp >> 6) & 0x3F));
                    out += (char)(0x80 | (cp & 0x3F));
                    continue;
                }
            }
            if (c < 0x80) out += (char)c;
            else if (c < 0x800) { out += (char)(0xC0 | (c >> 6)); out += (char)(0x80 | (c & 0x3F)); }
            else { out += (char)(0xE0 | (c >> 12)); out += (char)(0x80 | ((c >> 6) & 0x3F)); out += (char)(0x80 | (c & 0x3F)); }
        }
        return out;
    }
    static bool plausibleUtf16(const uint16_t* w, size_t n) {
        for (size_t i = 0; i < n; i++) {
            uint16_t c = w[i];
            if (c == 0) return n <= 1;   // ic NUL sadece bos stringde
            if (c < 0x20 && c != '\n' && c != '\t' && c != '\r') return false;
            if (c == 0xFFFE || c == 0xFFFF) return false;
        }
        return true;
    }

    // ---- QString (her iki cag) ----
    QtStr readQString(Addr qstrAddr) {
        QtStr r;
        if (!qstrAddr) return r;
        if (L.qt6Layout) {
            Addr d   = proc.readAddr(qstrAddr + L.qs_d);
            Addr ptr = proc.readAddr(qstrAddr + L.qs_ptr);
            int64_t size = (int64_t)proc.readAddr(qstrAddr + L.qs_size);
            if (size < 0 || size > (1 << 20) || !ptr) return r;
            if (ptr < 0x1000) return r;
            // ptr QArrayData header'dan sonra mi? (Qt6: ptr dogrudan char16_t*)
            std::vector<uint16_t> w((size_t)size);
            if (!proc.read(ptr, w.data(), (size_t)size * 2)) return r;
            if (!plausibleUtf16(w.data(), (size_t)size)) return r;
            r.utf8 = utf16ToUtf8(w.data(), (size_t)size);
            r.dataPtr = ptr; r.size = size; r.valid = true;
            return r;
        } else {
            // Qt5: QString { QStringData *d }
            Addr d = proc.readAddr(qstrAddr);
            if (!d || d < 0x1000) return r;
            int32_t size = proc.readI32(d + L.ad_size);
            if (size < 0 || size > (1 << 20)) return r;
            int64_t offset = (int64_t)proc.readAddr(d + L.ad_offset);   // qptrdiff
            Addr data = d + (Addr)offset;
            if (data < 0x1000) return r;
            std::vector<uint16_t> w((size_t)size);
            if (!proc.read(data, w.data(), (size_t)size * 2)) return r;
            if (!plausibleUtf16(w.data(), (size_t)size)) return r;
            r.utf8 = utf16ToUtf8(w.data(), (size_t)size);
            r.dataPtr = data; r.size = size; r.valid = true;
            return r;
        }
    }

    // ---- QList<T>: eleman isaretcileri ----
    // elemSize: eleman genisligi (QObject* gibi isaretciler icin ptrSize)
    std::vector<Addr> readListAddrs(Addr listAddr, size_t maxCount = 4096) {
        std::vector<Addr> out;
        if (!listAddr) return out;
        int es = proc.ptrSize();
        if (!L.listUsesHeader) {
            // Qt6: [d][ptr][size]
            Addr ptr = proc.readAddr(listAddr + L.ql_ptr);
            uint64_t size = proc.readAddr(listAddr + L.ql_size);
            if (!ptr || size > maxCount) return out;
            for (uint64_t i = 0; i < size; i++) {
                Addr e = proc.readAddr(ptr + i * es);
                out.push_back(e);
            }
        } else {
            // Qt5 — AMPRIK cift-format cozumleyici:
            //  (A) QListData: {ref(4), alloc(4), begin(4), end(4), array@16} — boyut=end-begin
            //  (B) QArrayData/QVector: {ref(4), size(4), alloc(4), pad(4), offset(8@16)}
            //  QStandardItem cocuklari (B), QWidget children QList<QObject*> (A) olabilir.
            Addr q = proc.readAddr(listAddr + L.ql_d);
            if (!q || q < 0x1000) return out;
            int32_t fA0 = proc.readI32(q + 4);       // alloc (A) / size (B)
            int32_t fA1 = proc.readI32(q + 8);       // begin (A) / alloc (B)
            int32_t fA2 = proc.readI32(q + 12);      // end (A) / pad (B)
            int64_t offB = (int64_t)proc.readAddr(q + 16);   // offset (B)
            // --- hipotez B once (QVector daha yaygin Qt5.15'te): size=fA0@+4 ---
            if (fA0 > 0 && (size_t)fA0 <= maxCount && offB > 0 && offB <= 0x100000) {
                Addr arrB = q + (Addr)offB;
                std::vector<Addr> cand;
                bool okB = true;
                for (int k = 0; k < fA0; k++) {
                    Addr e = proc.readAddr(arrB + (Addr)(k * es));
                    cand.push_back(e);
                }
                // gecerlilik: cogunluk 0 veya gecerli isaretci
                int good = 0;
                for (Addr e : cand)
                    if (e == 0 || (e > 0x10000 && e < 0x7fffffffffff)) good++;
                if (good >= (int)cand.size() * 9 / 10 && (int)cand.size() > 0) {
                    // ve ilk gecerli eleman QObject/QStandardItem geri-bag...
                    for (Addr e : cand) {
                        if (e < 0x10000) continue;
                        Addr ed = proc.readAddr(e + 8);
                        if (!ed || ed < 0x10000) continue;
                        Addr q1 = proc.readAddr(ed + 8);
                        if (q1 == e) break;   // QObject geri-bag OK
                        Addr q2 = proc.readAddr(ed + 40);
                        if (q2 == e) break;   // QStandardItem q_ptr@40 geri-bag OK
                        okB = false;          // hicbiri degilse supheli ama devam
                        break;
                    }
                    if (okB) return cand;
                }
            }
            // --- hipotez A (QListData): begin=fA1@+8, end=fA2@+12 ---
            int32_t sizeA = fA2 - fA1;
            if (sizeA > 0 && (size_t)sizeA <= maxCount && fA1 >= -4096 && fA1 <= 65536) {
                Addr arrA = q + 16;
                for (int k = 0; k < sizeA; k++) {
                    Addr e = proc.readAddr(arrA + (Addr)((fA1 + k) * es));
                    out.push_back(e);
                }
            }
        }
        return out;
    }

    // ---- QByteArray (Qt5/Qt6 ayni QArrayData duzeni) ----
    std::string readByteArray(Addr baAddr) {
        if (!baAddr) return {};
        // Qt6 QByteArray = QArrayDataPointer { d, ptr, size } — bayt dizisi ptr'de
        if (L.qt6Layout) {
            Addr ptr = proc.readAddr(baAddr + 8);
            uint64_t size = proc.readAddr(baAddr + 16);
            if (!ptr || size > (1 << 20)) return {};
            std::vector<char> b((size_t)size + 1);
            if (!proc.read(ptr, b.data(), (size_t)size)) return {};
            b[size] = 0;
            return std::string(b.data());
        }
        return {};
    }
};

} // namespace umvpqt
