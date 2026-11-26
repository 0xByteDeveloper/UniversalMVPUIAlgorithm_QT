// UMVPQT GOD STATE v3.2 — X11 Giriş Enjeksiyonu (wine hedefleri için Tier-1)
// ============================================================================
//  Windows SendMessage/PostMessage'ın Linux+wine dengi: XTEST sentetik
//  giriş (klavye + fare). dlopen(libX11/libXtst) — X yoksa sessiz devre dışı.
//  KANIT: VMProtect 3.9.4'te F9 (derleme kısayolu) → Test_64_*.vmp.exe üretimi.
// ============================================================================
#pragma once
#include "types.h"
#include <string>

namespace umvpqt {

class X11Input {
public:
    X11Input();
    ~X11Input();

    // libX11+Xtst yüklü ve DISPLAY ortamı var mı?
    static bool available();

    // ---- oturum ----
    // DISPLAY ortam değişkeninden açılır; close() ile kapatın (nullptr güvenli)
    static void* open();
    static void  close(void* dpy);

    // ---- pencere keşfi ----
    // X ağacındaki en büyük pencere (wine ana penceresi — odak hedefi)
    static unsigned long largestWindow(void* dpy);

    // ---- giriş ----
    static bool focusWindow(void* dpy, unsigned long win);
    static unsigned int keycodeForKeysym(void* dpy, unsigned long keysym);
    // pressRelease bitleri: 1=press, 2=release, 3=ikisi (tam tuş vuruşu)
    static bool sendKeycode(void* dpy, unsigned int keycode, int pressRelease);
    static bool clickAt(void* dpy, int x, int y, unsigned int button = 1);
    static bool motion(void* dpy, int x, int y);
    static bool button(void* dpy, unsigned int button, bool press);

    // ---- keysym çözümleyici ----
    // "F9", "Return", "a", "Ctrl"... → X11 keysym değeri
    static unsigned long keysymFromName(const std::string& name);

    struct Impl;
private:
    Impl* impl_;
};

} // namespace umvpqt
