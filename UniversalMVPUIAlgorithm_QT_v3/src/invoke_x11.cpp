// UMVPQT GOD STATE v3.2 — X11 Giriş Enjeksiyonu (wine hedefleri için Tier-1)
// ============================================================================
//  Windows SendMessage/PostMessage'ın Linux+wine dengi: XTEST sentetik
//  giriş olayları. VMProtect 3.9.4 kanıtında kullanıldı:
//    .vmp projesi yükle → XSetInputFocus → XTEST F9 → compile() NATIVE
//    çalışır (GUI thread kendi döngüsünde — ptrace/wineserver protokol
//    bozulması YOK) → 6,6 MB Test_64_*.vmp.exe üretildi.
//
//  Yüksek değerli nokta: XTEST olayları GERÇEK donanım-seviyesi olaylardır —
//  Qt bunları normal input gibi işler (send_event bayrağı yok — filtrelenmez).
//  libX11/libXtst dlopen ile — X olmayan sistemlerde sessiz devre dışı.
// ============================================================================
#include "umvpqt/invoke_x11.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <unistd.h>

namespace umvpqt {

// ------------------------------------------------------------------ impl ----
struct X11Input::Impl {
    // gerçek dlopen tablosu global g_libs'te (dosya özelinde) — Impl yalnız
    // RAII/kapsul taşır; sembol tablosu initX11() tarafından doldurulur.
    void* dummy = nullptr;
};

typedef void* (*fn_XOpenDisplay)(const char*);
typedef int   (*fn_XCloseDisplay)(void*);
typedef int   (*fn_XSync)(void*, int);
typedef unsigned int (*fn_XKeysymToKeycode)(void*, unsigned long);
typedef int   (*fn_XSetInputFocus)(void*, unsigned long, int, unsigned long);
typedef unsigned long (*fn_XDefaultRootWindow)(void*);
typedef int   (*fn_XQueryTree)(void*, unsigned long, unsigned long*, unsigned long*, unsigned long**, unsigned int*);
typedef int   (*fn_XFree)(void*);
typedef int   (*fn_XGetGeometry)(void*, unsigned long, unsigned long*, int*, int*, unsigned int*, unsigned int*, unsigned int*, unsigned int*);
typedef int   (*fn_XTestFakeKeyEvent)(void*, unsigned int, int, unsigned long);
typedef int   (*fn_XTestFakeButtonEvent)(void*, unsigned int, int, unsigned long);
typedef int   (*fn_XTestFakeMotionEvent)(void*, int, int, int, unsigned long);

struct Libs {
    void* x11 = nullptr, * xtst = nullptr;
    fn_XOpenDisplay openDisplay = nullptr;
    fn_XCloseDisplay closeDisplay = nullptr;
    fn_XSync sync = nullptr;
    fn_XKeysymToKeycode keysymToKeycode = nullptr;
    fn_XSetInputFocus setInputFocus = nullptr;
    fn_XDefaultRootWindow defaultRootWindow = nullptr;
    fn_XQueryTree queryTree = nullptr;
    fn_XFree xfree = nullptr;
    fn_XGetGeometry getGeometry = nullptr;
    fn_XTestFakeKeyEvent fakeKey = nullptr;
    fn_XTestFakeButtonEvent fakeButton = nullptr;
    fn_XTestFakeMotionEvent fakeMotion = nullptr;
    bool ok = false;
};

static Libs* g_libs = nullptr;

static bool initX11() {
    if (g_libs) return g_libs->ok;
    g_libs = new Libs();
    g_libs->x11 = dlopen("libX11.so.6", RTLD_NOW | RTLD_GLOBAL);
    if (!g_libs->x11) { g_libs->ok = false; return false; }
    // libXtst standart konumda yok olabılır (sandbox) — toolchain köklerini dene
    const char* xtstPaths[] = {
        "libXtst.so.6",
        "/home/z/my-project/vmprotect/wine_root/usr/lib/x86_64-linux-gnu/libXtst.so.6",
        "/home/z/my-project/toolchain/root/usr/lib/x86_64-linux-gnu/libXtst.so.6",
        nullptr
    };
    for (int i = 0; xtstPaths[i] && !g_libs->xtst; i++)
        g_libs->xtst = dlopen(xtstPaths[i], RTLD_NOW);
    if (!g_libs->xtst) { g_libs->ok = false; return false; }
    g_libs->openDisplay = (fn_XOpenDisplay)dlsym(g_libs->x11, "XOpenDisplay");
    g_libs->closeDisplay = (fn_XCloseDisplay)dlsym(g_libs->x11, "XCloseDisplay");
    g_libs->sync = (fn_XSync)dlsym(g_libs->x11, "XSync");
    g_libs->keysymToKeycode = (fn_XKeysymToKeycode)dlsym(g_libs->x11, "XKeysymToKeycode");
    g_libs->setInputFocus = (fn_XSetInputFocus)dlsym(g_libs->x11, "XSetInputFocus");
    g_libs->defaultRootWindow = (fn_XDefaultRootWindow)dlsym(g_libs->x11, "XDefaultRootWindow");
    g_libs->queryTree = (fn_XQueryTree)dlsym(g_libs->x11, "XQueryTree");
    g_libs->xfree = (fn_XFree)dlsym(g_libs->x11, "XFree");
    g_libs->getGeometry = (fn_XGetGeometry)dlsym(g_libs->x11, "XGetGeometry");
    g_libs->fakeKey = (fn_XTestFakeKeyEvent)dlsym(g_libs->xtst, "XTestFakeKeyEvent");
    g_libs->fakeButton = (fn_XTestFakeButtonEvent)dlsym(g_libs->xtst, "XTestFakeButtonEvent");
    g_libs->fakeMotion = (fn_XTestFakeMotionEvent)dlsym(g_libs->xtst, "XTestFakeMotionEvent");
    g_libs->ok = g_libs->openDisplay && g_libs->sync && g_libs->keysymToKeycode &&
                 g_libs->fakeKey && g_libs->fakeButton && g_libs->fakeMotion;
    return g_libs->ok;
}

X11Input::X11Input() : impl_(new Impl()) {}
X11Input::~X11Input() { delete impl_; }

// ---------------------------------------------------------------- kurulum --
bool X11Input::available() {
    const char* d = getenv("DISPLAY");
    return d && *d && initX11();
}

void* X11Input::open() {
    if (!available()) return nullptr;
    void* d = g_libs->openDisplay(nullptr);   // DISPLAY ortam değişkeninden
    return d;
}
void X11Input::close(void* dpy) {
    if (dpy && g_libs && g_libs->closeDisplay) g_libs->closeDisplay(dpy);
}

// ---------------------------------------------------- pencere keşfi (X) ----
unsigned long X11Input::largestWindow(void* dpy) {
    if (!dpy || !g_libs->ok) return 0;
    unsigned long root = g_libs->defaultRootWindow(dpy);
    unsigned long rootRet, parentRet, *children = nullptr;
    unsigned int nchildren = 0;
    if (!g_libs->queryTree(dpy, root, &rootRet, &parentRet, &children, &nchildren))
        return 0;
    unsigned long best = 0; unsigned long bestArea = 0;
    struct Frame { unsigned long id; int x, y; unsigned int w, h, bw, d; unsigned long root; int rx, ry; };
    for (unsigned i = 0; i < nchildren; i++) {
        // genişlik/yükseklik: XGetGeometry (pencere kendi boyutu)
        int rx = 0, ry = 0; unsigned int w = 0, h = 0, bw = 0, dp = 0; unsigned long rr = 0;
        if (g_libs->getGeometry(dpy, children[i], &rr, &rx, &ry, &w, &h, &bw, &dp)) {
            if ((unsigned long)w * h > bestArea) { bestArea = (unsigned long)w * h; best = children[i]; }
        }
        // çocukları da tara (bir seviye in: wine iç pencereleri)
        unsigned long r2, p2, *ch2 = nullptr; unsigned int n2 = 0;
        if (g_libs->queryTree(dpy, children[i], &r2, &p2, &ch2, &n2)) {
            for (unsigned k = 0; k < n2; k++) {
                int rx2 = 0, ry2 = 0; unsigned int w2 = 0, h2 = 0, bw2 = 0, dp2 = 0; unsigned long rr2 = 0;
                if (g_libs->getGeometry(dpy, ch2[k], &rr2, &rx2, &ry2, &w2, &h2, &bw2, &dp2)) {
                    if ((unsigned long)w2 * h2 > bestArea) { bestArea = (unsigned long)w2 * h2; best = ch2[k]; }
                }
            }
            if (ch2) g_libs->xfree(ch2);
        }
    }
    if (children) g_libs->xfree(children);
    return best;
}

// ------------------------------------------------------- odak + klavye ----
bool X11Input::focusWindow(void* dpy, unsigned long win) {
    if (!dpy || !win || !g_libs->ok) return false;
    // RevertToParent(1) + CurrentTime(0)
    if (!g_libs->setInputFocus(dpy, win, 1, 0)) { g_libs->sync(dpy, 0); return false; }
    g_libs->sync(dpy, 0);
    return true;
}

unsigned int X11Input::keycodeForKeysym(void* dpy, unsigned long keysym) {
    if (!dpy || !g_libs->ok) return 0;
    return g_libs->keysymToKeycode(dpy, keysym);
}

// (dosya-yerel yardımcı: tek tuş olayı gönder)
static bool x11_send_key(void* dpy, unsigned int keycode, bool press) {
    if (!dpy || !keycode || !g_libs->ok) return false;
    if (!g_libs->fakeKey(dpy, keycode, press ? 1 : 0, 0)) return false;
    g_libs->sync(dpy, 0);
    return true;
}

bool X11Input::sendKeycode(void* dpy, unsigned int keycode, int pressRelease) {
    if (pressRelease & 1) { if (!x11_send_key(dpy, keycode, true)) return false; usleep(30000); }
    if (pressRelease & 2) { if (!x11_send_key(dpy, keycode, false)) return false; }
    return true;
}

bool X11Input::motion(void* dpy, int x, int y) {
    if (!dpy || !g_libs->ok) return false;
    if (!g_libs->fakeMotion(dpy, -1, x, y, 0)) return false;   // -1 = default screen
    g_libs->sync(dpy, 0);
    return true;
}

bool X11Input::button(void* dpy, unsigned int button, bool press) {
    if (!dpy || !g_libs->ok) return false;
    if (!g_libs->fakeButton(dpy, button, press ? 1 : 0, 0)) return false;
    g_libs->sync(dpy, 0);
    return true;
}

bool X11Input::clickAt(void* dpy, int x, int y, unsigned int btn) {
    if (!motion(dpy, x, y)) return false;
    usleep(50000);
    if (!button(dpy, btn, true)) return false;
    usleep(60000);
    if (!button(dpy, btn, false)) return false;
    return true;
}

// ---------------------------------------------------- keysym çözümleyici ----
// X11 keysym tablosu (XK_): elle tanımlı minimal tablo — libX11'in
// XStringToKeysym sembolünü de kullanabilirdik ama isim tablosu sınırlı:
unsigned long X11Input::keysymFromName(const std::string& name) {
    struct KS { const char* n; unsigned long v; };
    static const KS tab[] = {
        {"F1",0xffbe},{"F2",0xffbf},{"F3",0xffc0},{"F4",0xffc1},{"F5",0xffc2},
        {"F6",0xffc3},{"F7",0xffc4},{"F8",0xffc5},{"F9",0xffc6},{"F10",0xffc7},
        {"F11",0xffc8},{"F12",0xffc9},{"Esc",0xff1b},{"Tab",0xff09},
        {"Return",0xff0d},{"Enter",0xff0d},{"Space",0x0020},{"BackSpace",0xff08},
        {"Delete",0xffff},{"Home",0xff50},{"End",0xff57},{"PageUp",0xff55},
        {"PageDown",0xff56},{"Left",0xff51},{"Up",0xff52},{"Right",0xff53},{"Down",0xff54},
        {"Shift",0xffe1},{"Ctrl",0xffe3},{"Alt",0xffe9},
    };
    for (auto& k : tab) if (name == k.n) return k.v;
    // tek karakter: ASCII keysym
    if (name.size() == 1 && (unsigned char)name[0] >= 32 && (unsigned char)name[0] < 127)
        return (unsigned long)(unsigned char)name[0];
    // libX11'in XStringToKeysym'i varsa dene
    if (g_libs && g_libs->x11) {
        typedef unsigned long (*fn_str2ks)(const char*);
        fn_str2ks f = (fn_str2ks)dlsym(g_libs->x11, "XStringToKeysym");
        if (f) { unsigned long v = f(name.c_str()); if (v && v != 0xffffffff) return v; }
    }
    return 0;
}

} // namespace umvpqt
