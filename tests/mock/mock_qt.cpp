// =============================================================================
// UMVP-QT // tests/mock/mock_qt.cpp — synthetic Qt process image builder.
// Everything the analyzer reads is constructed with the replica ABI offsets
// from src/qt_layout_db.h. The mock's own compiled functions NEVER dereference
// image addresses directly — image access always goes through the reader.
// =============================================================================
#include "mock_qt.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>

#include "qt_layout_db.h"

namespace umvpqt_mock {

using namespace umvpqt;

// ---------------------------------------------------------------------------
// side-effect counters
// ---------------------------------------------------------------------------
int g_on_button1_clicked = 0;
int g_on_check1_toggled = 0;
int g_lambda_fired = 0;
int g_button_click_slot = 0;
int g_mouse_press_overridden = 0;
int g_default_virtual_calls = 0;
int g_on_combo1_idx_changed = 0;
int g_combo_itemtext_calls = 0;

// active image pointer (mock metacalls read properties through it)
static MockImage* g_image = nullptr;

// ---------------------------------------------------------------------------
// real compiled code: metaObject() thunks  (mov rax,[rip+g]; ret)
// ---------------------------------------------------------------------------
static void* g_thunk_slot_meta[16] = {nullptr};

#define THUNK_SLOT(N) \
    extern "C" void* umvpqt_mock_thunk_##N() { return g_thunk_slot_meta[N]; }
THUNK_SLOT(0) THUNK_SLOT(1) THUNK_SLOT(2) THUNK_SLOT(3) THUNK_SLOT(4)
THUNK_SLOT(5) THUNK_SLOT(6) THUNK_SLOT(7) THUNK_SLOT(8) THUNK_SLOT(9)
THUNK_SLOT(10) THUNK_SLOT(11) THUNK_SLOT(12) THUNK_SLOT(13) THUNK_SLOT(14)
THUNK_SLOT(15)

static int g_thunk_next = 0;
static void* g_thunk_fns[16] = {
    (void*)&umvpqt_mock_thunk_0, (void*)&umvpqt_mock_thunk_1,
    (void*)&umvpqt_mock_thunk_2, (void*)&umvpqt_mock_thunk_3,
    (void*)&umvpqt_mock_thunk_4, (void*)&umvpqt_mock_thunk_5,
    (void*)&umvpqt_mock_thunk_6, (void*)&umvpqt_mock_thunk_7,
    (void*)&umvpqt_mock_thunk_8, (void*)&umvpqt_mock_thunk_9,
    (void*)&umvpqt_mock_thunk_10, (void*)&umvpqt_mock_thunk_11,
    (void*)&umvpqt_mock_thunk_12, (void*)&umvpqt_mock_thunk_13,
    (void*)&umvpqt_mock_thunk_14, (void*)&umvpqt_mock_thunk_15};

// ---------------------------------------------------------------------------
// real compiled code: handlers (the deep-disassembly targets)
// ---------------------------------------------------------------------------
static void Form1_on_button1_clicked(void* self) __attribute__((noinline));
static void Form1_on_button1_clicked(void* self) {
    ++g_on_button1_clicked;
    asm volatile("" :: "r"(self));     // keep 'self' alive across -O2
}
static void Form1_on_combo1_currentIndexChanged(void* self, int i) __attribute__((noinline));
static void Form1_on_combo1_currentIndexChanged(void* self, int i) {
    ++g_on_combo1_idx_changed;
    asm volatile("" :: "r"(self), "r"(i));
}
static void Form1_on_check1_toggled(void* self, bool b) __attribute__((noinline));
static void Form1_on_check1_toggled(void* self, bool b) {
    ++g_on_check1_toggled;
    asm volatile("" :: "r"(self), "r"(b));
}
static void button2_lambda_body(void* receiver, void** argv) {
    ++g_lambda_fired; (void)receiver; (void)argv;
}
static void QAbstractButton_click_impl(void* button) __attribute__((noinline));
static void QAbstractButton_click_impl(void* button) {
    ++g_button_click_slot;
    asm volatile("" :: "r"(button));
}
static void mock_mouse_press(void* w, void* e) {
    ++g_mouse_press_overridden; (void)w; (void)e;
}
static void mock_virtual_default(void* a) { ++g_default_virtual_calls; (void)a; }
static void mock_dtor(void*) {}

// helper: copy a QString object (in image) into a raw buffer
static void copy_qstring_to(MockImage* img, Address strObj, void* dst) {
    if (!img || !strObj) return;
    if (img->family() == QtFamily::Qt5) {
        uint64_t d = 0;
        img->reader()->read(strObj, &d, 8);
        std::memcpy(dst, &d, 8);
    } else {
        uint8_t buf[24];
        if (img->reader()->read(strObj, buf, 24)) std::memcpy(dst, buf, 24);
    }
}

// ---------------------------------------------------------------------------
// real compiled code: qt_static_metacall implementations (switch dispatch)
// ids: InvokeMetaMethod=0, ReadProperty=1
// ---------------------------------------------------------------------------
static void Form1_static_metacall(void* o, int c, int id, void** argv) {
    (void)argv;
    switch (c) {
    case 0:
        switch (id) {
        case 0: break;                                     // customSignal (signal)
        case 1: Form1_on_button1_clicked(o); break;
        case 2: ++g_lambda_fired; break;                    // on_button2_clicked
        case 3: Form1_on_combo1_currentIndexChanged(o, 0); break;
        case 4: Form1_on_check1_toggled(o, false); break;
        default: break;
        }
        break;
    default: break;
    }
}

static void QAbstractButton_static_metacall(void* o, int c, int id, void** argv) {
    switch (c) {
    case 0:
        switch (id) {
        case 5: QAbstractButton_click_impl(o); break;       // click()
        case 6: break;                                      // setChecked(bool)
        case 7: break;                                      // setText(QString)
        default: break;                                     // signals 0..4
        }
        break;
    case 1:
        switch (id) {
        case 0:                                             // text property
            if (argv && g_image)
                copy_qstring_to(g_image, g_image->textStringOf((Address)o), (void*)(uintptr_t)argv[0]);
            break;
        case 1:                                             // checked
            if (argv) *(bool*)(uintptr_t)argv[0] = false;
            break;
        default: break;
        }
        break;
    default: break;
    }
}

static void QComboBox_static_metacall(void* o, int c, int id, void** argv) {
    if (!g_image) return;
    switch (c) {
    case 0:
        switch (id) {
        case 8: {                                           // itemText(int) -> QString
            ++g_combo_itemtext_calls;
            if (!argv) break;
            int i = 0;
            std::memcpy(&i, (void*)(uintptr_t)argv[1], 4);
            const auto& items = g_image->comboItemsOf((Address)o);
            if (i >= 0 && (size_t)i < items.size())
                copy_qstring_to(g_image, g_image->comboItemString((Address)o, i),
                                (void*)(uintptr_t)argv[0]);
            break;
        }
        case 4: break;   // setCurrentIndex(int)
        case 5: break;   // setCurrentText(QString)
        case 6: break;   // addItem(QString)
        case 7: break;   // clear()
        default: break;  // signals 0..3
        }
        break;
    case 1:
        switch (id) {
        case 0:                                           // currentIndex
            if (argv) *(int*)(uintptr_t)argv[0] = g_image->comboIndexOf((Address)o);
            break;
        case 1: {                                         // currentText
            int idx = g_image->comboIndexOf((Address)o);
            if (argv && idx >= 0 &&
                (size_t)idx < g_image->comboItemsOf((Address)o).size())
                copy_qstring_to(g_image, g_image->comboItemString((Address)o, idx),
                                (void*)(uintptr_t)argv[0]);
            break;
        }
        case 2:                                           // count
            if (argv) *(int*)(uintptr_t)argv[0] = (int)g_image->comboItemsOf((Address)o).size();
            break;
        case 3:                                           // editable
            if (argv) *(bool*)(uintptr_t)argv[0] = false;
            break;
        default: break;
        }
        break;
    default: break;
    }
}

static void QWidget_static_metacall(void* o, int c, int id, void** argv) {
    (void)o; (void)c; (void)id; (void)argv;
}
static void QLabel_static_metacall(void* o, int c, int id, void** argv) {
    if (c == 1 && id == 0 && argv && g_image)               // text property
        copy_qstring_to(g_image, g_image->textStringOf((Address)o),
                        (void*)(uintptr_t)argv[0]);
}
static void QTimer_static_metacall(void* o, int c, int id, void** argv) {
    (void)o; (void)c; (void)id; (void)argv;
}

// QSlotObjectBase impls (read storage THROUGH THE READER — image addresses!)
extern "C" void umvpqt_mock_slotobj_impl_qt5(int which, void* this_, void* r,
                                             void** a, bool* ret) {
    if (which == 1 && g_image) {
        uint64_t fn = 0;
        g_image->reader()->read((Address)this_ + 16, &fn, 8);
        if (fn) ((void (*)(void*, void**))(uintptr_t)fn)(r, a);
    }
    if (ret) *ret = true;
}
extern "C" void umvpqt_mock_slotobj_impl_qt6(void* this_, void* r, void** a,
                                             int which, bool* ret) {
    if (which == 1 && g_image) {
        uint64_t fn = 0;
        g_image->reader()->read((Address)this_ + 16, &fn, 8);
        if (fn) ((void (*)(void*, void**))(uintptr_t)fn)(r, a);
    }
    if (ret) *ret = true;
}

// ---------------------------------------------------------------------------
// Impl
// ---------------------------------------------------------------------------
struct MockImage::Impl {
    Address codeLo = (Address)-1, codeHi = 0;
    std::map<std::string, Address> metas;
    std::map<std::string, Address> objects;
    std::map<Address, Address> textStr;                       // object -> QString obj
    std::map<Address, std::vector<Address>> comboItemStrs;    // object -> item QStrings
    std::map<Address, std::vector<std::string>> comboItemsTexts;
    std::map<Address, int> comboIndex;
    int nextConnId = 1;
    MemoryRegion* codeRegion = nullptr;
    ProcessInfo info;
    std::vector<MemoryRegion> regions;
    std::vector<ModuleInfo> modules;
    uint8_t* img = nullptr;

    class Reader : public IProcessReader {
    public:
        explicit Reader(Impl* impl) : impl_(impl) {}
        bool read(Address addr, void* buf, size_t len) override {
            if (addr >= kBase && addr + len <= kBase + kSize) {
                std::memcpy(buf, impl_->img + (addr - kBase), len);
                return true;
            }
            // code + globals of the hosting test binary
            if (addr > 0x10000 && addr < (Address)-0x10000) {
                std::memcpy(buf, (void*)(uintptr_t)addr, len);
                return true;
            }
            return false;
        }
        const std::vector<MemoryRegion>& regions() override { return impl_->regions; }
        const std::vector<ModuleInfo>& modules() override { return impl_->modules; }
        ProcessInfo info() const override { return impl_->info; }
    private:
        Impl* impl_;
    };
    Reader* reader = nullptr;
};

MockImage::MockImage(QtFamily fam) : fam_(fam) {
    buf_.assign(kSize, 0);
    impl_ = new Impl;
    impl_->img = buf_.data();
    impl_->info.pid = 4242;
    impl_->info.name = "mock_qt_target";
    impl_->info.arch = Arch::X64;
    MemoryRegion reg;
    reg.start = kBase;
    reg.end = kBase + kSize;
    reg.perms = 1 | 2 | 4;     // RWX so embedded vtables pass exec checks
    reg.name = "mock_heap";
    impl_->regions.push_back(reg);
    ModuleInfo m;
    m.name = fam == QtFamily::Qt5 ? "Qt5Core.dll" : "Qt6Core.dll";
    m.base = kBase;
    m.size = kSize;
    m.isQtCore = true;
    m.qtFlavor = fam == QtFamily::Qt5 ? "qt5" : "qt6";
    impl_->modules.push_back(m);
    g_image = this;
}

MockImage::~MockImage() {
    if (g_image == this) g_image = nullptr;
    delete impl_->reader;
    delete impl_;
}

IProcessReader* MockImage::reader() {
    if (!impl_->reader) impl_->reader = new Impl::Reader(impl_);
    return impl_->reader;
}

Address MockImage::alloc(size_t n, size_t align) {
    size_t p = (cursor_ + align - 1) & ~(align - 1);
    if (p + n > kSize) { std::fprintf(stderr, "mock image OOM\n"); std::abort(); }
    cursor_ = p + n;
    return kBase + p;
}

void MockImage::poke8(Address at, uint64_t v) {
    std::memcpy(buf_.data() + (at - kBase), &v, 8);
}

void MockImage::registerCode(void* fn) {
    Address a = (Address)fn;
    if (a < impl_->codeLo) impl_->codeLo = a;
    if (a > impl_->codeHi) impl_->codeHi = a;
    if (!impl_->codeRegion) {
        MemoryRegion r;
        r.start = impl_->codeLo;
        r.end = impl_->codeHi + 0x1000;
        r.perms = 1 | 4;   // RX
        r.name = "mock_code";
        r.moduleBase = 0;
        impl_->regions.push_back(r);
        impl_->codeRegion = &impl_->regions.back();
    } else {
        impl_->codeRegion->start = impl_->codeLo;
        impl_->codeRegion->end = impl_->codeHi + 0x1000;
    }
}

Address MockImage::newString(const std::string& utf8) {
    std::vector<char16_t> w(utf8.begin(), utf8.end());
    if (fam_ == QtFamily::Qt5) {
        // QStringData header (24B) + inline chars at +24
        Address data = alloc(24 + w.size() * 2 + 8, 16);
        uint8_t hdr[24] = {0};
        int32_t sz = (int32_t)w.size();
        int32_t ref = -1;
        int64_t off = 24;
        std::memcpy(hdr + 0, &ref, 4);
        std::memcpy(hdr + 4, &sz, 4);
        std::memcpy(hdr + 16, &off, 8);
        std::memcpy(buf_.data() + (data - kBase), hdr, 24);
        if (!w.empty())
            std::memcpy(buf_.data() + (data - kBase) + 24, w.data(), w.size() * 2);
        Address obj = alloc(8);
        poke8(obj, data);
        return obj;
    }
    // Qt6: {d, ptr, size}; chars after a 16-byte QArrayData header
    Address chars = alloc(16 + w.size() * 2 + 8, 16);
    uint8_t hdr[16] = {0};
    int32_t ref = -1;
    std::memcpy(hdr, &ref, 4);
    std::memcpy(buf_.data() + (chars - kBase), hdr, 16);
    if (!w.empty())
        std::memcpy(buf_.data() + (chars - kBase) + 16, w.data(), w.size() * 2);
    Address obj = alloc(24);
    poke8(obj, 0);
    poke8(obj + 8, chars + 16);
    uint64_t szv = (uint64_t)w.size();
    std::memcpy(buf_.data() + (obj + 16 - kBase), &szv, 8);
    return obj;
}

Address MockImage::newMetaObject(const char* className, Address super,
                                 const std::vector<MethodSpec>& methods,
                                 int signalCount,
                                 const std::vector<PropSpec>& props,
                                 void* staticMetacall) {
    const QtLayout& L = fam_ == QtFamily::Qt5 ? *layout_db_qt5_x64()
                                              : *layout_db_qt6_x64();
    const int ipm = L.mop_ints_per_method;

    // ---- string table ----
    std::vector<std::string> strs{std::string(className)};
    for (const auto& m : methods) {
        strs.push_back(m.name);
        for (int a = 0; a < m.argc; ++a) strs.push_back("int");
    }
    for (const auto& p : props) {
        strs.push_back(p.name);
        strs.push_back(p.type);
    }

    Address stringdata = 0;
    if (fam_ == QtFamily::Qt5) {
        Address entries = alloc(strs.size() * 24 + 16, 16);
        size_t charsTotal = 0;
        for (auto& s : strs) charsTotal += (s.size() + 2) * 2;
        Address chars = alloc(charsTotal + 16, 16);
        size_t coff = 0;
        for (size_t i = 0; i < strs.size(); ++i) {
            Address entry = entries + i * 24;
            uint8_t hdr[24] = {0};
            int32_t sz = (int32_t)strs[i].size();
            int32_t ref = -1;
            int64_t off = (int64_t)(chars + coff - entry);
            std::memcpy(hdr, &ref, 4);
            std::memcpy(hdr + 4, &sz, 4);
            std::memcpy(hdr + 16, &off, 8);
            std::memcpy(buf_.data() + (entry - kBase), hdr, 24);
            std::vector<char16_t> w(strs[i].begin(), strs[i].end());
            if (!w.empty())
                std::memcpy(buf_.data() + (chars + coff - kBase), w.data(), w.size() * 2);
            coff += (strs[i].size() + 1) * 2;
        }
        stringdata = entries;
    } else {
        Address u32s = alloc(strs.size() * 8 + 16, 16);
        size_t charsTotal = 0;
        for (auto& s : strs) charsTotal += (s.size() + 2);
        Address chars = alloc(charsTotal * 2 + 16, 16);
        size_t coff = 0;
        for (size_t i = 0; i < strs.size(); ++i) {
            uint32_t off = (uint32_t)((chars + coff) - u32s);
            uint32_t len = (uint32_t)strs[i].size();
            std::memcpy(buf_.data() + (u32s + i * 8 - kBase), &off, 4);
            std::memcpy(buf_.data() + (u32s + i * 8 + 4 - kBase), &len, 4);
            std::vector<char16_t> w(strs[i].begin(), strs[i].end());
            if (!w.empty())
                std::memcpy(buf_.data() + (chars + coff - kBase), w.data(), w.size() * 2);
            coff += (strs[i].size() + 1) * 2;
        }
        stringdata = u32s;
    }

    // ---- data array: header(14) + methods + params + props ----
    std::vector<uint32_t> methodEntries;
    std::vector<std::vector<uint32_t>> paramIdxsOf;
    size_t strIdx = 1;   // 0 = className
    for (const auto& m : methods) {
        uint32_t nameIdx = (uint32_t)strIdx++;
        std::vector<uint32_t> pi;
        for (int a = 0; a < m.argc; ++a) pi.push_back((uint32_t)strIdx++);
        paramIdxsOf.push_back(pi);
        methodEntries.push_back(nameIdx);
        methodEntries.push_back((uint32_t)m.argc);
        methodEntries.push_back(0);   // parameters (filled below)
        methodEntries.push_back(0);   // tag
        methodEntries.push_back((uint32_t)m.flags);
        if (ipm >= 6) methodEntries.push_back(0);   // metaTypeOffset
    }
    std::vector<uint32_t> paramsBlock;
    for (auto& pi : paramIdxsOf)
        for (auto idx : pi) paramsBlock.push_back(idx | 0x80000000u);
    // parameters field: data[parameters+1+a] = param typeinfo
    uint32_t paramsStart = 14 + (uint32_t)methodEntries.size();
    size_t pi = 0;
    for (size_t i = 0; i < methods.size(); ++i) {
        methodEntries[i * ipm + 2] = paramsStart + (uint32_t)pi - 1;
        pi += (size_t)methods[i].argc;
    }
    std::vector<uint32_t> propEntries;
    for (const auto& p : props) {
        uint32_t nameIdx = (uint32_t)strIdx++;
        uint32_t typeIdx = (uint32_t)strIdx++;
        propEntries.push_back(nameIdx);
        propEntries.push_back(typeIdx | 0x80000000u);
        propEntries.push_back((uint32_t)p.flags);
    }

    std::vector<uint32_t> header(14, 0);
    header[0] = (uint32_t)(fam_ == QtFamily::Qt5 ? 8 : 12);   // revision
    header[1] = 0;                                            // className idx
    header[5] = (uint32_t)methods.size();                     // methodCount
    header[6] = 14;                                           // methodData
    header[7] = (uint32_t)props.size();                       // propertyCount
    header[8] = 14 + (uint32_t)methodEntries.size() +
                (uint32_t)paramsBlock.size();                 // propertyData
    header[13] = (uint32_t)signalCount;

    std::vector<uint32_t> all = header;
    all.insert(all.end(), methodEntries.begin(), methodEntries.end());
    all.insert(all.end(), paramsBlock.begin(), paramsBlock.end());
    all.insert(all.end(), propEntries.begin(), propEntries.end());
    Address dataArr = alloc(all.size() * 4 + 16, 16);
    std::memcpy(buf_.data() + (dataArr - kBase), all.data(), all.size() * 4);

    // ---- QMetaObject struct ----
    const int moSize = fam_ == QtFamily::Qt5 ? 48 : 56;
    Address mo = alloc(moSize, 16);
    std::memset(buf_.data() + (mo - kBase), 0, moSize);
    poke8(mo + L.mo_superdata, super);
    poke8(mo + L.mo_stringdata, stringdata);
    poke8(mo + L.mo_data, dataArr);
    poke8(mo + L.mo_static_metacall, (uint64_t)(uintptr_t)staticMetacall);

    impl_->metas[className] = mo;
    if (staticMetacall) registerCode(staticMetacall);
    return mo;
}

Address MockImage::newVtable(Address metaObject, void* metacallFn,
                             void* overrideMousePress) {
    // 64 slots, zero padded: slots >= vtable end are ZERO so override
    // comparison sees null-vs-null and skips (no false positives).
    Address vtable = alloc(64 * 8, 8);
    std::memset(buf_.data() + (vtable - kBase), 0, 64 * 8);
    int t = g_thunk_next++ % 16;
    g_thunk_slot_meta[t] = (void*)(uintptr_t)metaObject;
    poke8(vtable + 0 * 8, (uint64_t)(uintptr_t)&mock_dtor);
    poke8(vtable + 1 * 8, (uint64_t)(uintptr_t)&mock_dtor);
    poke8(vtable + 2 * 8, (uint64_t)(uintptr_t)g_thunk_fns[t]);
    poke8(vtable + 3 * 8, (uint64_t)(uintptr_t)&mock_virtual_default);
    poke8(vtable + 4 * 8, (uint64_t)(uintptr_t)metacallFn);
    for (int s = 5; s <= 13; ++s)
        poke8(vtable + (Address)s * 8, (uint64_t)(uintptr_t)&mock_virtual_default);
    poke8(vtable + 14 * 8,
          (uint64_t)(uintptr_t)(overrideMousePress ? overrideMousePress
                                                   : (void*)&mock_virtual_default));
    poke8(vtable + 15 * 8, (uint64_t)(uintptr_t)&mock_virtual_default);
    registerCode((void*)&mock_dtor);
    registerCode((void*)&mock_virtual_default);
    registerCode(metacallFn);
    if (overrideMousePress) registerCode(overrideMousePress);
    return vtable;
}

Address MockImage::newQObject(const ObjectSpec& spec) {
    const QtLayout& L = fam_ == QtFamily::Qt5 ? *layout_db_qt5_x64()
                                              : *layout_db_qt6_x64();
    const bool qt5 = fam_ == QtFamily::Qt5;
    const size_t privSize = qt5 ? 88 : 112;
    const size_t tail = 256;
    const bool makeWidgetData = spec.rect[2] > 0;

    // ExtraData + objectName
    Address extra = 0;
    if (spec.objectName) {
        Address nameStr = newString(spec.objectName);
        if (qt5) {
            extra = alloc(48, 8);
            std::memset(buf_.data() + (extra - kBase), 0, 48);
            uint64_t dptr = 0;                     // QString {QStringData* d}
            std::memcpy(&dptr, buf_.data() + (nameStr - kBase), 8);
            poke8(extra + 40, dptr);               // objectName@40 (default build)
        } else {
            extra = alloc(128, 8);
            std::memset(buf_.data() + (extra - kBase), 0, 128);
            std::memcpy(buf_.data() + (extra + 96 - kBase),
                        buf_.data() + (nameStr - kBase), 24);
        }
    }

    // QObjectPrivate (+ tail for text/combo heuristics)
    Address d = alloc(privSize + tail, 16);
    std::memset(buf_.data() + (d - kBase), 0, privSize + tail);
    poke8(d + L.obj_qptr, 0);                     // patched below
    poke8(d + L.obj_parent, spec.parent);
    poke8(d + L.obj_children, 0);                 // empty list (Qt5 null = shared-null)
    if (!qt5) poke8(d + L.obj_children + 16, 0);  // QADP size 0
    poke8(d + L.obj_bits, makeWidgetData ? 1 : 0);   // isWidget bit
    poke8(d + L.priv_extra, extra);
    poke8(d + L.priv_conn, 0);

    Address textStrObj = 0;
    if (spec.text) {
        textStrObj = newString(spec.text);
        std::memcpy(buf_.data() + (d + privSize - kBase),
                    buf_.data() + (textStrObj - kBase), qt5 ? 8 : 24);
    }
    std::vector<Address> itemStrs;
    if (!spec.comboItems.empty()) {
        for (auto& s : spec.comboItems) itemStrs.push_back(newString(s));
        size_t off = privSize + 8;                // combo private tail
        std::memcpy(buf_.data() + (d + off - kBase), &spec.comboIndex, 4);
        int cnt = (int)spec.comboItems.size();
        std::memcpy(buf_.data() + (d + off + 4 - kBase), &cnt, 4);
        for (size_t i = 0; i < itemStrs.size(); ++i) {
            Address slot = d + off + 8 + (Address)i * (qt5 ? 8 : 24);
            std::memcpy(buf_.data() + (slot - kBase),
                        buf_.data() + (itemStrs[i] - kBase), qt5 ? 8 : 24);
        }
    }

    // QWidgetData
    Address widgetData = 0;
    if (makeWidgetData) {
        widgetData = alloc(72, 16);
        uint8_t wd[72] = {0};
        std::memcpy(wd + 0, &spec.winId, 8);
        std::memcpy(wd + 12, &spec.windowFlags, 4);
        uint32_t wordA = 0;
        if (spec.inShow) wordA |= (1u << 10);
        std::memcpy(wd + 16, &wordA, 4);
        int32_t crect[4] = {spec.rect[0], spec.rect[1],
                            spec.rect[0] + spec.rect[2] - 1,
                            spec.rect[1] + spec.rect[3] - 1};
        std::memcpy(wd + 24, crect, 16);
        std::memcpy(buf_.data() + (widgetData - kBase), wd, 72);
    }

    // object
    Address obj = alloc(makeWidgetData ? 32 : 16, 16);
    std::memset(buf_.data() + (obj - kBase), 0, makeWidgetData ? 32 : 16);
    poke8(obj + 0, spec.vtable);
    poke8(obj + 8, d);
    if (makeWidgetData) {
        poke8(obj + 16, spec.vtable);
        poke8(obj + 24, widgetData);
    }

    // backrefs + bookkeeping
    poke8(d + L.obj_qptr, obj);
    if (textStrObj) impl_->textStr[obj] = textStrObj;
    if (!itemStrs.empty()) {
        impl_->comboItemStrs[obj] = itemStrs;
        impl_->comboItemsTexts[obj] = spec.comboItems;
        impl_->comboIndex[obj] = spec.comboIndex;
    }
    if (spec.objectName) impl_->objects[spec.objectName] = obj;
    return obj;
}

void MockImage::addChild(Address parentObj, Address childObj) {
    const QtLayout& L = fam_ == QtFamily::Qt5 ? *layout_db_qt5_x64()
                                              : *layout_db_qt6_x64();
    IProcessReader* rd = reader();
    Address pd = rd->readPtr(parentObj + 8);
    std::vector<Address> kids;
    if (fam_ == QtFamily::Qt5) {
        Address cd = rd->readPtr(pd + L.obj_children);
        if (cd) {
            int32_t begin = 0, end = 0;
            rd->readI32(cd + 8, &begin);
            rd->readI32(cd + 12, &end);
            for (int i = begin; i < end; ++i)
                kids.push_back(rd->readPtr(cd + 16 + (Address)i * 8));
        }
    } else {
        int64_t size = 0;
        rd->read(pd + L.obj_children + 16, &size, 8);
        Address ptr = rd->readPtr(pd + L.obj_children + 8);
        for (int i = 0; i < size; ++i) kids.push_back(rd->readPtr(ptr + (Address)i * 8));
    }
    kids.push_back(childObj);

    if (fam_ == QtFamily::Qt5) {
        Address nd = alloc(16 + kids.size() * 8 + 16, 16);
        uint8_t hdr[16] = {0};
        int32_t ref = 1, allocv = 16, begin = 0, end = (int32_t)kids.size();
        std::memcpy(hdr + 0, &ref, 4);
        std::memcpy(hdr + 4, &allocv, 4);
        std::memcpy(hdr + 8, &begin, 4);
        std::memcpy(hdr + 12, &end, 4);
        std::memcpy(buf_.data() + (nd - kBase), hdr, 16);
        for (size_t i = 0; i < kids.size(); ++i) poke8(nd + 16 + i * 8, kids[i]);
        poke8(pd + L.obj_children, nd);
    } else {
        Address nodes = alloc(kids.size() * 8 + 16, 16);
        std::memset(buf_.data() + (nodes - kBase), 0, kids.size() * 8 + 16);
        for (size_t i = 0; i < kids.size(); ++i) poke8(nodes + i * 8, kids[i]);
        poke8(pd + L.obj_children + 0, 0);
        poke8(pd + L.obj_children + 8, nodes);
        uint64_t n = kids.size();
        std::memcpy(buf_.data() + (pd + L.obj_children + 16 - kBase), &n, 8);
    }
    Address cdPriv = rd->readPtr(childObj + 8);
    poke8(cdPriv + L.obj_parent, parentObj);
}

void MockImage::addMethodConnection(Address senderObj, int signalAbsIndex,
                                    Address receiverObj, int slotAbsIndex,
                                    void* receiverStaticMetacall) {
    const QtLayout& L = fam_ == QtFamily::Qt5 ? *layout_db_qt5_x64()
                                              : *layout_db_qt6_x64();
    IProcessReader* rd = reader();
    Address d = rd->readPtr(senderObj + 8);
    Address cd = rd->readPtr(d + L.priv_conn);
    if (!cd) {
        cd = alloc(40, 16);
        std::memset(buf_.data() + (cd - kBase), 0, 40);
        poke8(d + L.priv_conn, cd);
    }
    Address sv = rd->readPtr(cd + L.cd_signalvector);
    if (!sv) {
        sv = alloc(16 + 17 * 16, 16);     // header + lists for -1..15
        std::memset(buf_.data() + (sv - kBase), 0, 16 + 17 * 16);
        uint64_t allocv = 16;
        std::memcpy(buf_.data() + (sv + 8 - kBase), &allocv, 8);
        poke8(cd + L.cd_signalvector, sv);
    }

    Address conn = alloc(L.conn_sizeof, 16);
    std::memset(buf_.data() + (conn - kBase), 0, L.conn_sizeof);
    poke8(conn + L.conn_sender, senderObj);
    poke8(conn + L.conn_receiver, receiverObj);
    poke8(conn + L.conn_callfn, (uint64_t)(uintptr_t)receiverStaticMetacall);
    uint16_t mo16 = (uint16_t)(slotAbsIndex & 0xFFFF);
    uint16_t mr16 = (uint16_t)((slotAbsIndex >> 16) & 0xFFFF);
    std::memcpy(buf_.data() + (conn + L.conn_moffset - kBase), &mo16, 2);
    std::memcpy(buf_.data() + (conn + L.conn_mrelative - kBase), &mr16, 2);
    uint32_t bits = 0;
    bits |= (uint32_t)(signalAbsIndex & 0x07FFFFFF);
    bits |= (1u << 27);                             // connectionType = 1 (direct)
    std::memcpy(buf_.data() + (conn + L.conn_bits - kBase), &bits, 4);
    uint32_t idv = (uint32_t)(impl_->nextConnId++);
    std::memcpy(buf_.data() + (conn + L.conn_id - kBase), &idv, 4);
    uint32_t refv = 2;
    std::memcpy(buf_.data() + (conn + L.conn_ref - kBase), &refv, 4);

    Address listAddr = sv + L.sv_lists + (Address)(signalAbsIndex + 1) * 16;
    Address first = rd->readPtr(listAddr);
    if (!first) {
        poke8(listAddr, conn);
        poke8(listAddr + 8, conn);
    } else {
        Address last = rd->readPtr(listAddr + 8);
        poke8(last + L.conn_nextlist, conn);
        poke8(listAddr + 8, conn);
    }
    registerCode(receiverStaticMetacall);
}

void MockImage::addFunctorConnection(Address senderObj, int signalAbsIndex,
                                     Address receiverObj, void* slotObjImplFn,
                                     void* storageFn) {
    const QtLayout& L = fam_ == QtFamily::Qt5 ? *layout_db_qt5_x64()
                                              : *layout_db_qt6_x64();
    IProcessReader* rd = reader();
    Address slotObj = alloc(32, 16);
    std::memset(buf_.data() + (slotObj - kBase), 0, 32);
    poke8(slotObj + 0, (uint64_t)(uintptr_t)slotObjImplFn);
    uint32_t refS = 2;
    std::memcpy(buf_.data() + (slotObj + 8 - kBase), &refS, 4);
    poke8(slotObj + 16, (uint64_t)(uintptr_t)storageFn);
    poke8(slotObj + 24, 0);
    registerCode(slotObjImplFn);
    registerCode(storageFn);

    Address d = rd->readPtr(senderObj + 8);
    Address cd = rd->readPtr(d + L.priv_conn);
    if (!cd) {
        cd = alloc(40, 16);
        std::memset(buf_.data() + (cd - kBase), 0, 40);
        poke8(d + L.priv_conn, cd);
    }
    Address sv = rd->readPtr(cd + L.cd_signalvector);
    if (!sv) {
        sv = alloc(16 + 17 * 16, 16);
        std::memset(buf_.data() + (sv - kBase), 0, 16 + 17 * 16);
        uint64_t allocv = 16;
        std::memcpy(buf_.data() + (sv + 8 - kBase), &allocv, 8);
        poke8(cd + L.cd_signalvector, sv);
    }

    Address conn = alloc(L.conn_sizeof, 16);
    std::memset(buf_.data() + (conn - kBase), 0, L.conn_sizeof);
    poke8(conn + L.conn_sender, senderObj);
    poke8(conn + L.conn_receiver, receiverObj);
    poke8(conn + L.conn_callfn, slotObj);
    uint16_t z16 = 0;
    std::memcpy(buf_.data() + (conn + L.conn_moffset - kBase), &z16, 2);
    std::memcpy(buf_.data() + (conn + L.conn_mrelative - kBase), &z16, 2);
    uint32_t bits = 0;
    bits |= (uint32_t)(signalAbsIndex & 0x07FFFFFF);
    bits |= (1u << 27);
    const int typeBits = fam_ == QtFamily::Qt5 ? 3 : 2;
    bits |= (1u << (27 + typeBits));   // isSlotObject = 1
    std::memcpy(buf_.data() + (conn + L.conn_bits - kBase), &bits, 4);
    uint32_t idv = (uint32_t)(impl_->nextConnId++);
    std::memcpy(buf_.data() + (conn + L.conn_id - kBase), &idv, 4);
    uint32_t refv2 = 2;
    std::memcpy(buf_.data() + (conn + L.conn_ref - kBase), &refv2, 4);

    Address listAddr = sv + L.sv_lists + (Address)(signalAbsIndex + 1) * 16;
    Address first = rd->readPtr(listAddr);
    if (!first) {
        poke8(listAddr, conn);
        poke8(listAddr + 8, conn);
    } else {
        Address last = rd->readPtr(listAddr + 8);
        poke8(last + L.conn_nextlist, conn);
        poke8(listAddr + 8, conn);
    }
}

Address MockImage::textStringOf(Address object) const {
    auto it = impl_->textStr.find(object);
    return it == impl_->textStr.end() ? 0 : it->second;
}
Address MockImage::comboItemString(Address object, int i) const {
    auto it = impl_->comboItemStrs.find(object);
    if (it == impl_->comboItemStrs.end()) return 0;
    if (i < 0 || (size_t)i >= it->second.size()) return 0;
    return it->second[(size_t)i];
}
const std::vector<std::string>& MockImage::comboItemsOf(Address object) const {
    static const std::vector<std::string> empty;
    auto it = impl_->comboItemsTexts.find(object);
    return it == impl_->comboItemsTexts.end() ? empty : it->second;
}
int MockImage::comboIndexOf(Address object) const {
    auto it = impl_->comboIndex.find(object);
    return it == impl_->comboIndex.end() ? -1 : it->second;
}

MockImage::World MockImage::buildWorld() {
    World w;
    const auto SIG = 0x02 | 0x04;   // public signal
    const auto SLOT = 0x02 | 0x08;  // public slot
    const auto INV = 0x02;          // public Q_INVOKABLE

    // ---- meta objects ------------------------------------------------------
    w.meta_QObject = newMetaObject("QObject", 0,
        {{"destroyed", 1, SIG}, {"objectNameChanged", 1, SIG}, {"deleteLater", 0, SLOT}},
        2, {}, (void*)&QWidget_static_metacall);
    w.meta_QWidget = newMetaObject("QWidget", w.meta_QObject,
        {{"windowTitleChanged", 1, SIG}, {"windowIconChanged", 1, SIG},
         {"show", 0, SLOT}, {"hide", 0, SLOT}, {"setWindowTitle", 1, SLOT}},
        2,
        {{"windowTitle", "QString", 0x3}, {"enabled", "bool", 0x3}, {"visible", "bool", 0x1}},
        (void*)&QWidget_static_metacall);
    w.meta_QMainWindow = newMetaObject("QMainWindow", w.meta_QWidget,
        {{"iconSizeChanged", 1, SIG}, {"setCentralWidget", 1, SLOT}},
        1, {}, (void*)&QWidget_static_metacall);
    w.meta_QDialog = newMetaObject("QDialog", w.meta_QWidget,
        {{"accepted", 0, SIG}, {"rejected", 0, SIG},
         {"accept", 0, SLOT}, {"reject", 0, SLOT}},
        2, {}, (void*)&QWidget_static_metacall);
    w.meta_QAbstractButton = newMetaObject("QAbstractButton", w.meta_QWidget,
        {{"clicked", 1, SIG}, {"clicked", 0, SIG}, {"pressed", 0, SIG},
         {"released", 0, SIG}, {"toggled", 1, SIG},
         {"click", 0, SLOT}, {"setChecked", 1, SLOT}, {"setText", 1, SLOT}},
        5,
        {{"text", "QString", 0x3}, {"checked", "bool", 0x3}},
        (void*)&QAbstractButton_static_metacall);
    w.meta_QPushButton = newMetaObject("QPushButton", w.meta_QAbstractButton,
        {}, 0, {}, (void*)&QAbstractButton_static_metacall);
    w.meta_QComboBox = newMetaObject("QComboBox", w.meta_QWidget,
        {{"currentIndexChanged", 1, SIG}, {"currentTextChanged", 1, SIG},
         {"activated", 1, SIG}, {"highlighted", 1, SIG},
         {"setCurrentIndex", 1, SLOT}, {"setCurrentText", 1, SLOT},
         {"addItem", 1, SLOT}, {"clear", 0, SLOT},
         {"itemText", 1, INV}},
        4,
        {{"currentIndex", "int", 0x3}, {"currentText", "QString", 0x3},
         {"count", "int", 0x1}, {"editable", "bool", 0x3}},
        (void*)&QComboBox_static_metacall);
    w.meta_QLabel = newMetaObject("QLabel", w.meta_QWidget,
        {{"setText", 1, SLOT}, {"clear", 0, SLOT}},
        0, {{"text", "QString", 0x3}}, (void*)&QLabel_static_metacall);
    w.meta_QCheckBox = newMetaObject("QCheckBox", w.meta_QAbstractButton,
        {}, 0, {}, (void*)&QAbstractButton_static_metacall);
    w.meta_Form1 = newMetaObject("Form1", w.meta_QMainWindow,
        {{"customSignal", 1, SIG},
         {"on_button1_clicked", 0, SLOT},
         {"on_button2_clicked", 0, SLOT},
         {"on_combo1_currentIndexChanged", 1, SLOT},
         {"on_check1_toggled", 1, SLOT}},
        1, {}, (void*)&Form1_static_metacall);
    w.meta_MyButton = newMetaObject("MyButton", w.meta_QPushButton,
        {}, 0, {}, (void*)&QAbstractButton_static_metacall);
    w.meta_QTimer = newMetaObject("QTimer", w.meta_QObject,
        {{"timeout", 0, SIG}, {"start", 1, SLOT}, {"stop", 0, SLOT}},
        1, {}, (void*)&QTimer_static_metacall);

    // ---- vtables -----------------------------------------------------------
    auto vt = [&](Address mo, void* mc, void* ov = nullptr) {
        return newVtable(mo, mc, ov);
    };
    Address vt_QWidget = vt(w.meta_QWidget, (void*)&QWidget_static_metacall);
    Address vt_QMainWindow = vt(w.meta_QMainWindow, (void*)&QWidget_static_metacall);
    Address vt_QDialog = vt(w.meta_QDialog, (void*)&QWidget_static_metacall);
    Address vt_QPushButton = vt(w.meta_QPushButton, (void*)&QAbstractButton_static_metacall);
    Address vt_QComboBox = vt(w.meta_QComboBox, (void*)&QComboBox_static_metacall);
    Address vt_QLabel = vt(w.meta_QLabel, (void*)&QLabel_static_metacall);
    Address vt_QCheckBox = vt(w.meta_QCheckBox, (void*)&QAbstractButton_static_metacall);
    Address vt_Form1 = vt(w.meta_Form1, (void*)&Form1_static_metacall);
    Address vt_MyButton = vt(w.meta_MyButton, (void*)&QAbstractButton_static_metacall,
                             (void*)&mock_mouse_press);
    Address vt_QTimer = vt(w.meta_QTimer, (void*)&QTimer_static_metacall);

    // ---- objects ------------------------------------------------------------
    {
        ObjectSpec s;
        s.metaObject = w.meta_Form1;
        s.vtable = vt_Form1;
        s.objectName = "Form1";
        
        s.rect[0] = 60;
s.rect[1] = 60;
s.rect[2] = 700;
s.rect[3] = 520;
s.winId = 0x00021A01;
        s.inShow = true;
        s.windowFlags = 0x1;
        w.form1 = newQObject(s);
    }
    {
        ObjectSpec s;
        s.metaObject = w.meta_QDialog;
        s.vtable = vt_QDialog;
        s.objectName = "Form2";
        
        s.rect[0] = 900;
s.rect[1] = 200;
s.rect[2] = 300;
s.rect[3] = 200;
s.winId = 0x00021B02;
        s.inShow = false;
        s.windowFlags = 0x3;
        w.form2 = newQObject(s);
    }
    {
        ObjectSpec s;
        s.metaObject = w.meta_QPushButton;
        s.vtable = vt_QPushButton;
        s.objectName = "button1";
        s.text = "Kaydet";
        
        s.rect[0] = 20;
s.rect[1] = 60;
s.rect[2] = 120;
s.rect[3] = 28;
s.winId = 0x00021C03;
        w.button1 = newQObject(s);
    }
    {
        ObjectSpec s;
        s.metaObject = w.meta_QPushButton;
        s.vtable = vt_QPushButton;
        s.objectName = "button2";
        s.text = "Iptal";
        
        s.rect[0] = 160;
s.rect[1] = 60;
s.rect[2] = 120;
s.rect[3] = 28;
s.winId = 0x00021C04;
        w.button2 = newQObject(s);
    }
    {
        ObjectSpec s;
        s.metaObject = w.meta_QComboBox;
        s.vtable = vt_QComboBox;
        s.objectName = "combo1";
        
        s.rect[0] = 20;
s.rect[1] = 100;
s.rect[2] = 160;
s.rect[3] = 24;
s.winId = 0x00021C05;
        s.comboItems = {"A", "B", "C"};
        s.comboIndex = 1;
        w.combo1 = newQObject(s);
    }
    {
        ObjectSpec s;
        s.metaObject = w.meta_QLabel;
        s.vtable = vt_QLabel;
        s.objectName = "label1";
        s.text = "Aciklama:";
        
        s.rect[0] = 20;
s.rect[1] = 130;
s.rect[2] = 200;
s.rect[3] = 20;
s.winId = 0x00021C06;
        w.label1 = newQObject(s);
    }
    {
        ObjectSpec s;
        s.metaObject = w.meta_QCheckBox;
        s.vtable = vt_QCheckBox;
        s.objectName = "check1";
        s.text = "Aktif";
        
        s.rect[0] = 20;
s.rect[1] = 160;
s.rect[2] = 100;
s.rect[3] = 20;
s.winId = 0x00021C07;
        w.check1 = newQObject(s);
    }
    {
        ObjectSpec s;
        s.metaObject = w.meta_MyButton;
        s.vtable = vt_MyButton;
        s.objectName = "myButton";
        s.text = "Ozel";
        
        s.rect[0] = 20;
s.rect[1] = 190;
s.rect[2] = 120;
s.rect[3] = 28;
s.winId = 0x00021C08;
        w.myButton = newQObject(s);
    }
    {
        ObjectSpec s;
        s.metaObject = w.meta_QTimer;
        s.vtable = vt_QTimer;
        s.objectName = "timer1";
        s.rect[0] = 0;
s.rect[1] = 0;
s.rect[2] = 0;
s.rect[3] = 0;     // non-widget: no QWidgetData
        w.timer1 = newQObject(s);
    }

    // ---- children ------------------------------------------------------------
    addChild(w.form1, w.button1);
    addChild(w.form1, w.button2);
    addChild(w.form1, w.combo1);
    addChild(w.form1, w.label1);
    addChild(w.form1, w.check1);
    addChild(w.form1, w.myButton);

    // ---- connections ---------------------------------------------------------
    // button1 clicked (abs sig 4) -> Form1::on_button1_clicked (abs method 11)
    addMethodConnection(w.button1, 4, w.form1, 11, (void*)&Form1_static_metacall);
    // button2 clicked -> lambda (functor)
    addFunctorConnection(w.button2, 4, w.form2 /* context */,
                         fam_ == QtFamily::Qt5 ? (void*)&umvpqt_mock_slotobj_impl_qt5
                                               : (void*)&umvpqt_mock_slotobj_impl_qt6,
                         (void*)&button2_lambda_body);
    // check1 toggled (abs sig 8) -> Form1::on_check1_toggled (abs method 14)
    addMethodConnection(w.check1, 8, w.form1, 14, (void*)&Form1_static_metacall);
    // combo1: currentIndexChanged HICBAGLI DEGIL — "olayi olmayan obje" testi

    // register all code
    for (void* f : g_thunk_fns) registerCode(f);
    registerCode((void*)&Form1_on_button1_clicked);
    registerCode((void*)&Form1_on_combo1_currentIndexChanged);
    registerCode((void*)&Form1_on_check1_toggled);
    registerCode((void*)&QAbstractButton_click_impl);
    registerCode((void*)&Form1_static_metacall);
    registerCode((void*)&QAbstractButton_static_metacall);
    registerCode((void*)&QComboBox_static_metacall);
    registerCode((void*)&QWidget_static_metacall);
    registerCode((void*)&QLabel_static_metacall);
    registerCode((void*)&QTimer_static_metacall);
    registerCode((void*)&button2_lambda_body);
    registerCode((void*)&umvpqt_mock_slotobj_impl_qt5);
    registerCode((void*)&umvpqt_mock_slotobj_impl_qt6);
    registerCode((void*)&mock_mouse_press);
    return w;
}

} // namespace umvpqt_mock
