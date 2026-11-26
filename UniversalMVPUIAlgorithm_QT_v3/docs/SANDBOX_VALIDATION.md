# Sandbox Doğrulama — V3.2 (GERÇEK VMProtect 3.9.4 DAHİL)

## Tarih sırasına göre ölçümler

| # | Ne | Sonuç |
|---|---|---|
| 1 | Wine 10.0 rootless kurulumu (apt-get download + dpkg -x + wineshim LD_PRELOAD + zlib1.dll) | ✔ cmd koştu: `SANDBOX_WINE_OK`, sahte Win 10.0.19043 |
| 2 | VMProtect 3.9.4 boş açılış (Xvfb :95) | ✔ süreç ayakta; 394 QObject, 3 form (pencere gizli — argümansız modda start sayfası) |
| 3 | VMProtect.exe **Test_64.exe** argümanıyla | ✔ **4171 QObject / 391 widget / 3 form / 151 sınıf**; MainWindow 141 çocuklu |
| 4 | MainWindow metaobject | ✔ 82 slot isimle çözüldü (notify, addFunction, compile, treeItemDoubleClicked…) |
| 5 | qt_static_metacall ABI | ✔ hex kanıt: `85 d2 0f85... 49 8b f9 48 8b d9 41 83 f8 51` (edx=_c, rcx=_o, r8=_id, r9=_a) |
| 6 | MainWindow::addFunction() (ptrace + qt_static_metacall, MS-ABI) | ✔ FunctionDialog + QLineEdit + QLabel bellekte (`[YENI WIDGET]` olayları) |
| 7 | MainWindow::compile() (ptrace yolu) | ✔ ProgressDialog + QProgressBar oluştu; wineserver bozulması → storm-abort güvenli geri dönüş (süreç HAYATTA) |
| 8 | XTEST F9 (XSetInputFocus + XTestFakeKeyEvent) | ✔ **Test_64_MemoryProtection.vmp.exe üretildi: 6.631.323 bayt** |
| 9 | Toplu üretim (tools/vmp_batch.sh + ajan xkey F9) | ✔ **11/11 varyant** (sandbox_proof/ içinde GERÇEK PE32+ dosyalar) |
| 10 | Entegrasyon testleri (mock hedefler, v2 devri) | ✔ **69/69 PASS** (Qt6 + Qt5) |
| 11 | VMProtect-benzeri mock senaryo (v2 devri) | ✔ 15/15 PASS (81/81 komut) |

## V3.2'de düzeltilen kalıcılık hataları ("duraksama" şikayetinin kökenleri)

1. **findWidget formları görmüyordu**: MainWindow::addFunction gibi form-slot
   çağrıları "widget bulunamadi" ile başarısız. → formWidgetCache_ eklendi.
2. **waitTarget olay fırtınasında sonsuz döngü**: waitpid olayları zaman
   aşımını hiç göremiyordu → ajan takılıyordu. → her turda süre denetimi.
3. **SIGSEGV fırtınası-abort**: hedef sürekli fault ediyorsa (anti-debug /
   yanlış thread) 8+ fault sonunda çağrı düşürülür, kayıtlar onarılırmalı
   geri yüklenir — süreç ölmez.
4. **wine pipe-read kırılımı**: PTRACE_INTERRUPT pipe_read içinde kesiyordu;
   kayıtlar rax=-512 (ERESTARTSYS) ile dönünce wineserver protokolü kırılıyordu
   ("seh invalid frame"). → fixSyscallRestart (rip-=2, rax=orig_rax).
5. **mmap scratch yığında SEH reddi**: callee gerçek yığın sınırları dışında
   SEH karesi kurunca wine "invalid frame not in stack limits" ile öldürüyordu.
   → çağrı çerçevesi GERÇEK thread yığınına taşındı (hold_.rsp - 0x6000).
