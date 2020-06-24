#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "opensslhelper.h"

#include "openssl/aes.h"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      ssl_helper_(new openssl::OpensslHelper) {
  ui->setupUi(this);

  connect(this, &MainWindow::update_log_signal, this,
          &MainWindow::update_log_slot);

  connect(ui->gene_pairkey_btn, &QPushButton::clicked, this,
          &MainWindow::gene_pairkey_slot);
  connect(ui->sign_btn, &QPushButton::clicked, this, &MainWindow::sign_slot);
  connect(ui->verify_btn, &QPushButton::clicked, this,
          &MainWindow::verify_slot);

  connect(ui->base64_en_btn, &QPushButton::clicked, this,
          &MainWindow::base64_test_slot);

  connect(ui->aes_en_btn, &QPushButton::clicked, this,
          &MainWindow::aes_encrypt_slot);
  connect(ui->aes_de_btn, &QPushButton::clicked, this,
          &MainWindow::aes_decrypt_slot);
}

MainWindow::~MainWindow() { delete ui; }

void MainWindow::update_log_slot(const QString& log) {
  ui->log_text->append(log);
}

void MainWindow::gene_pairkey_slot() { ssl_helper_->GeneratePairkeyRSA(); }

void MainWindow::sign_slot() {
  //    int iRet = 0;
  //    unsigned char uchash[256] = {0};//计算的摘要

  //    if(PRI_KEY_FILE == NULL) {
  //        printf("parameter error\r\n");
  //        return;
  //    }

  //    FILE *fp = NULL;
  //    //打开文件
  //    fp = fopen(PRI_KEY_FILE, "rt");
  //    if ( fp == NULL ) {
  //        printf("fopen [%s] error\r\n", PRI_KEY_FILE);
  //        return;
  //    }
  //    RSA *rsa_pri_key = RSA_new();
  //    //读取PEM证书文件
  //    if(PEM_read_RSAPrivateKey(fp, &rsa_pri_key, 0, 0) == NULL) {
  //        RSA_free(rsa_pri_key);
  //        fclose(fp);
  //        printf("PEM_read_RSAPrivateKey error\r\n");
  //        return;
  //    }
  //    //关闭句柄
  //    fclose(fp);

  //    std::string in_data("hello world");
  ////    unsigned char* signed_data = new unsigned char[1024];
  ////    signed_data = new unsigned char[1024];
  //    unsigned char signed_data[2048] = { 0 };
  //    unsigned int siglen = 0;

  //    //使用的SHA256计算摘要，若是SHA1则替换成对应的函数
  //    SHA256((const unsigned char*)in_data.c_str(), in_data.length(), uchash);
  //    std::string hash_str((char*)uchash);

  //    //计算签名，前三个参数传入SHA256对应的参数
  //    iRet = RSA_sign(NID_sha256, (const unsigned char*)hash_str.c_str(),
  //                    hash_str.length(), signed_data, &siglen, rsa_pri_key);
  //    Q_EMIT update_log_signal("siglen: " + QString::number(siglen));

  //    if(1 != iRet) {
  //        RSA_free(rsa_pri_key);
  //        delete[] signed_data;
  //        return;
  //    }
  ////    signed_data_ = (char*)signed_data;

  //////    char* signdata_base64 = new char[1024];
  //    char signdata_base64[1024] = { 0 };
  //    base64_encode((char*)signed_data, strlen((char*)signed_data),
  //                  signdata_base64, false);

  //    signed_data_ = signdata_base64;
  ////    Q_EMIT update_log_signal("signed_data: " +
  ////                             QString::fromStdString(signed_data_));
  ////    Q_EMIT update_log_signal("signed_data len: " +
  ////                             QString::number(signed_data_.length()));

  ////    delete[] signed_data;

  ////    printf("RSA_sign ok\n");
  //    RSA_free(rsa_pri_key);
}

void MainWindow::verify_slot() {
  //    if(PUB_KEY_FILE == NULL) {
  //        printf("parameter error\r\n");
  //        return;
  //    }

  //    RSA *rsa_pub_key = RSA_new();

  //    FILE *fp = NULL;
  //    fp = fopen(PUB_KEY_FILE, "rt");
  //    if( fp == NULL ) {
  //        RSA_free(rsa_pub_key);
  //        printf("fopen [%s] error\r\n", PUB_KEY_FILE);
  //        return;
  //    }

  //    if(NULL ==PEM_read_RSAPublicKey(fp, &rsa_pub_key, 0, 0)) {
  //        RSA_free(rsa_pub_key);
  //        fclose(fp);
  //        printf("PEM_read_RSA_PUBKEY error\r\n");
  //        return;
  //    }
  //    fclose(fp);

  //    std::string in_data("hello world");

  //    int iRet = 0;
  //    unsigned char uchash[256] = {0};//计算的摘要
  //    //使用的SHA256计算摘要，若是其他算法则替换成对应的函数
  ////    SHA1(src, srclen, uchash);
  //    SHA256((const unsigned char*)in_data.c_str(), in_data.length(), uchash);
  //    std::string hash_str((char*)uchash);

  ////    char* signed_data_decode = new char[1024];
  //    char signed_data_decode[2048] = {0};
  //    base64_decode(signed_data_.c_str(),
  //    signed_data_.length(),signed_data_decode, false);
  //    Q_EMIT update_log_signal("len: " +
  //    QString::number(strlen(signed_data_decode)));

  //    //计算签名，前三个参数传入SHA1对应的参数
  //    iRet = RSA_verify(NID_sha256, (const unsigned char*)hash_str.c_str(),
  //                      hash_str.length(),
  //                      (const unsigned char*)(signed_data_decode),
  //                      strlen(signed_data_decode), rsa_pub_key);
  ////    iRet = RSA_verify(NID_sha256, (const unsigned char*)hash_str.c_str(),
  ////                      hash_str.length(),
  ////                      (const unsigned char*)(signed_data_.c_str()),
  ////                      signed_data_.length(), rsa_pub_key);
  //    if(1 != iRet) {
  //        Q_EMIT update_log_signal("verify error");
  //        unsigned long ulErr = ERR_get_error();
  //        char szErrMsg[1024] = {0};
  //        char *pTmp = NULL;
  //        pTmp = ERR_error_string(ulErr,szErrMsg); //
  //        格式：error:errId:库:函数:原因
  //        Q_EMIT update_log_signal("pTmp: " + QString::fromStdString(pTmp));

  //        RSA_free(rsa_pub_key);
  //        return;
  //    }
  //    Q_EMIT update_log_signal("RSA_verify ok");
  ////    delete[] signed_data_decode;

  //    RSA_free(rsa_pub_key);
}

void MainWindow::base64_test_slot() {
  std::string instr = "hello world";
  Q_EMIT update_log_signal("base64 data: " + QString::fromStdString(instr));

  std::string encode_instr = ssl_helper_->EncodeBase64(instr, false);
  Q_EMIT update_log_signal("base64 encode data: " +
                           QString::fromStdString(encode_instr));

  std::string decode_instr = ssl_helper_->DecodeBase64(encode_instr, false);
  Q_EMIT update_log_signal("base64 decode data: " +
                           QString::fromStdString(decode_instr));
}

void MainWindow::aes_encrypt_slot() {
    std::string indata = "加解密测试明文字符串向量在运算过程中会被改变，为了"
                         "之后可以正常解密，拷贝一份副本使用向量在运算过程中"
                         "会被改变，为了之后可以正常解密，拷贝一份副本使用";
    std::string iv = "1234567890abcdef";
    std::string encrypt_data = ssl_helper_->AesEncrypt(indata, iv);
    Q_EMIT update_log_signal("aes encrypt data: " +
                             QString::fromStdString(encrypt_data));
}

void MainWindow::aes_decrypt_slot() {
//    std::string indata = "加解密测试明文字符串向量在运算过程中会被改变，为了"
//                         "之后可以正常解密，拷贝一份副本使用向量在运算过程中"
//                         "会被改变，为了之后可以正常解密，拷贝一份副本使用";
    std::string indata = "hello world";
    std::string iv = "1234567890abcdef";
    std::string encrypt_data = ssl_helper_->AesEncrypt(indata, iv);
    Q_EMIT update_log_signal("aes encrypt data: " +
                             QString::fromStdString(encrypt_data));

    std::string iv1 = "1234567890abcdef";
    std::string decrypt_data = ssl_helper_->AesDecrypt(encrypt_data, iv1);
    Q_EMIT update_log_signal("aes decrypt data: " +
                             QString::fromStdString(decrypt_data));
}
