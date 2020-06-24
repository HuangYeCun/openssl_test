#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <memory>

namespace openssl {
class OpensslHelper;
}

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();

Q_SIGNALS:
  void update_log_signal(const QString &log);

 private slots:
  void update_log_slot(const QString &log);
  void gene_pairkey_slot();
  void sign_slot();
  void verify_slot();

  void base64_test_slot();

  void aes_encrypt_slot();
  void aes_decrypt_slot();

 private:
  int base64_encode(const char *in_str, int in_len, char *out_str,
                    bool with_new_line);
  int base64_decode(const char *in_str, int in_len, char *out_str,
                    bool with_new_line);

 private:
  Ui::MainWindow *ui;

  std::unique_ptr<openssl::OpensslHelper> ssl_helper_;
};

#endif  // MAINWINDOW_H
