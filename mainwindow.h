#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

Q_SIGNALS:
    void update_log_signal(const QString& log);

private slots:
    void update_log_slot(const QString& log);
    void gene_pairkey_slot();
    void sign_slot();
    void verify_slot();

    void base64_test_slot();

private:
    int base64_encode(const char *in_str, int in_len, char *out_str);
    int base64_decode(const char *in_str, int in_len, char *out_str);

private:
    Ui::MainWindow *ui;

    std::string signed_data_;
    unsigned char* signed_data;
};

#endif // MAINWINDOW_H
