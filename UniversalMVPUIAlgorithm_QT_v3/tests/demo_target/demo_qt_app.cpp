// UMVPQT GOD STATE — Demo Test Hedefi (Qt menu barindiran surec)
// ============================================================================
//  Bu uygulama UMVPQT scanner'in test hedefidir:
//   - Form1: AnaPencere (butonlar, label, lineEdit, comboBox, checkBox)
//     * btnEventli     -> on_btnEventli_clicked() SLOTU VAR
//     * btnBos         -> HICBIR SLOT YOK (bos buton tespiti icin)
//   - Form2: AyarDialog (baslangicta gizli, btnEventli ile acilir)
//   - MyCanvas: paintEvent OVERRIDE'LI ozel widget
//   - Monitor testi: +4 sn'de AyarDialog otomatik acilir, +9 sn'de kapanir
//  QT_QPA_PLATFORM=offscreen ile basitir (sandbox).
// ============================================================================
#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QDialog>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include <QtGui/QPaintEvent>
#include <QtGui/QPainter>
#include <QtCore/QTimer>
#include <QtCore/QDateTime>
#include <cstdio>

// ---------------------------------------------------------- MyCanvas ----
class MyCanvas : public QWidget {
    Q_OBJECT
public:
    explicit MyCanvas(QWidget* p = nullptr) : QWidget(p) {
        setObjectName("canvasOzel");
        setMinimumSize(120, 60);
    }
protected:
    void paintEvent(QPaintEvent*) override {      // GOD override tespiti icin
        QPainter p(this);
        p.fillRect(rect(), Qt::darkBlue);
        p.setPen(Qt::yellow);
        p.drawText(rect(), Qt::AlignCenter, "CANVAS_PAINT_OVERRIDE");
    }
};

// --------------------------------------------------------- AyarDialog ----
class AyarDialog : public QDialog {
    Q_OBJECT
public:
    explicit AyarDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setObjectName("Form2_Ayarlar");
        setWindowTitle("Ayarlar Penceresi");
        setModal(false);
        auto* l = new QVBoxLayout(this);
        auto* lbl = new QLabel("Dil secimi:", this);
        lbl->setObjectName("lblDil");
        auto* combo = new QComboBox(this);
        combo->setObjectName("comboDil");
        combo->addItem("Turkce");
        combo->addItem("English");
        combo->addItem("Deutsch");
        combo->addItem("Francais");
        combo->setCurrentIndex(1);
        auto* kaydet = new QPushButton("Kaydet", this);
        kaydet->setObjectName("btnKaydet");
        connect(kaydet, &QPushButton::clicked, this, &AyarDialog::onKaydet);
        auto* vazgec = new QPushButton("Vazgec", this);   // slot YOK
        vazgec->setObjectName("btnVazgec");
        l->addWidget(lbl);
        l->addWidget(combo);
        l->addWidget(kaydet);
        l->addWidget(vazgec);
        setLayout(l);
        resize(300, 160);
    }
signals:
    void ayarlarDegisti(int secim);
public slots:
    void onKaydet() {
        fprintf(stderr, "[demo] AyarDialog::onKaydet cagrildi\n");
        emit ayarlarDegisti(1);
    }
};

// -------------------------------------------------------- AnaPencere ----
class AnaPencere : public QMainWindow {
    Q_OBJECT
public:
    explicit AnaPencere(QWidget* parent = nullptr) : QMainWindow(parent) {
        setObjectName("Form1_AnPencere");
        setWindowTitle("UMVPQT Demo Ana Form");

        auto* central = new QWidget(this);
        central->setObjectName("centralWidget");
        auto* l = new QVBoxLayout(central);

        auto* lblBaslik = new QLabel("GOD STATE QT ANALIZ DEMO", central);
        lblBaslik->setObjectName("lblBaslik");

        auto* lblDurum = new QLabel("Durum: bekleniyor...", central);
        lblDurum->setObjectName("lblDurum");

        btnEventli = new QPushButton("Event'li Buton (Tikla)", central);
        btnEventli->setObjectName("btnEventli");
        connect(btnEventli, &QPushButton::clicked, this, &AnaPencere::onBtnEventli);

        btnBos = new QPushButton("Bos Buton (event YOK)", central);
        btnBos->setObjectName("btnBos");   // HICBIR baglanti yok!

        auto* editAd = new QLineEdit("umvpqt_test_metni", central);
        editAd->setObjectName("editAd");

        auto* comboSeviye = new QComboBox(central);
        comboSeviye->setObjectName("comboSeviye");
        comboSeviye->addItem("Kolay");
        comboSeviye->addItem("Orta");
        comboSeviye->addItem("Zor");
        comboSeviye->addItem("IMKANSIZ");
        comboSeviye->setCurrentIndex(2);

        auto* chkOtomatik = new QCheckBox("Otomatik tarama", central);
        chkOtomatik->setObjectName("chkOtomatik");
        chkOtomatik->setChecked(true);
        connect(chkOtomatik, &QCheckBox::toggled, this, &AnaPencere::onChkOtomatik);

        canvas = new MyCanvas(central);

        l->addWidget(lblBaslik);
        l->addWidget(btnEventli);
        l->addWidget(btnBos);
        l->addWidget(editAd);
        l->addWidget(comboSeviye);
        l->addWidget(chkOtomatik);
        l->addWidget(lblDurum);
        l->addWidget(canvas);
        central->setLayout(l);
        setCentralWidget(central);
        resize(420, 420);

        dialog = new AyarDialog(this);

        // MONITOR TESTI: +4s dialog acilir, +9s kapanir, +11s yeni widget dogar
        QTimer::singleShot(4000, this, [this] { dialog->show(); });
        QTimer::singleShot(9000, this, [this] { dialog->hide(); });
        QTimer::singleShot(11000, this, [this] { dinamikWidgetEkle(); });
    }
public slots:
    void onBtnEventli() {
        fprintf(stderr, "[demo] AnaPencere::onBtnEventli cagrildi\n");
        dialog->show();
    }
    void onChkOtomatik(bool on) {
        fprintf(stderr, "[demo] chkOtomatik toggled=%d\n", (int)on);
    }
    void dinamikWidgetEkle() {
        auto* lblYeni = new QLabel("MONITOR_YENI_WIDGET", this->centralWidget());
        lblYeni->setObjectName("lblYeniDinamik");
        lblYeni->move(10, 200);
        lblYeni->show();
    }
private:
    QPushButton* btnEventli = nullptr;
    QPushButton* btnBos = nullptr;
    AyarDialog* dialog = nullptr;
    MyCanvas* canvas = nullptr;
};

#include "demo_qt_app_moc.inc"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    AnaPencere w;
    w.show();
    // sureklilik: 20 sn sonra kapan (test betigi app'i oldurmese de olur)
    QTimer::singleShot(20000, &app, &QApplication::quit);
    return app.exec();
}
