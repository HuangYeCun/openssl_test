#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <assert.h>

#include "include/openssl/rsa.h"
#include "include/openssl/md5.h"
#include "include/openssl/sha.h"
#include "include/openssl/pem.h"
#include <include/openssl/err.h>

// ---- rsa非对称加解密 ---- //
#define KEY_LENGTH  1024             // 密钥长度
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    signed_data_(""){
    ui->setupUi(this);

    connect(this, &MainWindow::update_log_signal,
            this, &MainWindow::update_log_slot);
    connect(ui->gene_pairkey_btn, &QPushButton::clicked,
            this, &MainWindow::gene_pairkey_slot);
    connect(ui->sign_btn, &QPushButton::clicked,
            this, &MainWindow::sign_slot);
    connect(ui->verify_btn, &QPushButton::clicked,
            this, &MainWindow::verify_slot);

    connect(ui->base64_en_btn, &QPushButton::clicked,
            this, &MainWindow::base64_test_slot);
//    connect(ui->base64_de_btn, &QPushButton::clicked,
//            this, &MainWindow::verify_slot);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::update_log_slot(const QString& log) {
    ui->log_text->append(log);
}

void MainWindow::gene_pairkey_slot() {
    // 公私密钥对
    size_t pri_len = 0;
    size_t pub_len = 0;
    char *pri_key = NULL;
    char *pub_key = NULL;

    // 生成密钥对
    RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);
//    RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_F4, NULL, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    // 获取长度
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    // 密钥对读取到字符串
    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    std::string strKey[2];
    // 存储密钥对
    strKey[0] = pub_key;
    strKey[1] = pri_key;

    // 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private key开头的）
    FILE *pubFile = fopen(PUB_KEY_FILE, "w");
    if (pubFile == NULL) {
        assert(false);
        return;
    }
    fputs(pub_key, pubFile);
    fclose(pubFile);

    FILE *priFile = fopen(PRI_KEY_FILE, "w");
    if (priFile == NULL) {
        assert(false);
        return;
    }
    fputs(pri_key, priFile);
    fclose(priFile);

    // 内存释放
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    Q_EMIT update_log_signal("pub_key: " + QString::fromStdString(pub_key));
    Q_EMIT update_log_signal("pub_key len : " +
                             QString::number(strlen(pub_key)));
    Q_EMIT update_log_signal("pri_key: " + QString::fromStdString(pri_key));
    Q_EMIT update_log_signal("pri_key len: " +
                             QString::number(strlen(pri_key)));

    free(pri_key);
    free(pub_key);
}

void MainWindow::sign_slot() {
    int iRet = 0;
    unsigned char uchash[256] = {0};//计算的摘要

    if(PRI_KEY_FILE == NULL) {
        printf("parameter error\r\n");
        return;
    }

    FILE *fp = NULL;
    //打开文件
    fp = fopen(PRI_KEY_FILE, "rt");
    if ( fp == NULL ) {
        printf("fopen [%s] error\r\n", PRI_KEY_FILE);
        return;
    }
    RSA *rsa_pri_key = RSA_new();
    //读取PEM证书文件
    if(PEM_read_RSAPrivateKey(fp, &rsa_pri_key, 0, 0) == NULL) {
        RSA_free(rsa_pri_key);
        fclose(fp);
        printf("PEM_read_RSAPrivateKey error\r\n");
        return;
    }
    //关闭句柄
    fclose(fp);

    std::string in_data("hello world");
//    unsigned char* signed_data = new unsigned char[1024];
    signed_data = new unsigned char[1024];
    unsigned int siglen = 0;

    //使用的SHA256计算摘要，若是SHA1则替换成对应的函数
    SHA256((const unsigned char*)in_data.c_str(), in_data.length(), uchash);
    std::string hash_str((char*)uchash);

    char* hash_base64 = new char[1024];
    base64_encode(hash_str.c_str(), hash_str.length(), hash_base64);
    Q_EMIT update_log_signal("hash: " + QString::fromStdString(hash_base64));

    //计算签名，前三个参数传入SHA256对应的参数
    iRet = RSA_sign(NID_sha256, (const unsigned char*)hash_base64,
                    strlen(hash_base64), signed_data, &siglen, rsa_pri_key);
    Q_EMIT update_log_signal("siglen: " + QString::number(siglen));
    delete[] hash_base64;
    if(1 != iRet) {
        RSA_free(rsa_pri_key);
        delete[] signed_data;
        return;
    }
//    signed_data_ = (char*)signed_data;

    char* signdata_base64 = new char[1024];
    base64_encode((char*)signed_data, strlen((char*)signed_data), signdata_base64);

//    char* sign_data_in = (char*)signed_data;
//    int sign_data_in_len = strlen(sign_data_in);
//    char* decode_base64 = new char[1024];
//    memset(decode_base64, 0, 1024);
//    base64_decode(signdata_base64, strlen(signdata_base64), decode_base64);
//    int decode_base64_len = strlen(decode_base64);
//    if(0 == strcmp(sign_data_in, decode_base64)) {
//        Q_EMIT update_log_signal(" equal ");
//    } else {
//        Q_EMIT update_log_signal(" no equal ");
//    }
//    delete[] signdata_base64;
//    delete[] decode_base64;

    signed_data_ = signdata_base64;
    Q_EMIT update_log_signal("signed_data: " +
                             QString::fromStdString(signed_data_));
    Q_EMIT update_log_signal("signed_data len: " + QString::number(signed_data_.length()));

    delete[] signed_data;
    delete[] signdata_base64;

    printf("RSA_sign ok\n");
    RSA_free(rsa_pri_key);

}

void MainWindow::verify_slot() {
    if(PUB_KEY_FILE == NULL) {
        printf("parameter error\r\n");
        return;
    }

    RSA *rsa_pub_key = RSA_new();

    FILE *fp = NULL;
    fp = fopen(PUB_KEY_FILE, "rt");
    if( fp == NULL ) {
        RSA_free(rsa_pub_key);
        printf("fopen [%s] error\r\n", PUB_KEY_FILE);
        return;
    }

    if(NULL ==PEM_read_RSAPublicKey(fp, &rsa_pub_key, 0, 0)) {
        RSA_free(rsa_pub_key);
        fclose(fp);
        printf("PEM_read_RSA_PUBKEY error\r\n");
        return;
    }
    fclose(fp);

    std::string in_data("hello world");

    int iRet = 0;
    unsigned char uchash[256] = {0};//计算的摘要
    //使用的SHA256计算摘要，若是其他算法则替换成对应的函数
//    SHA1(src, srclen, uchash);
    SHA256((const unsigned char*)in_data.c_str(), in_data.length(), uchash);
    std::string hash_str((char*)uchash);

    char* hash_base64 = new char[1024];
    base64_encode(hash_str.c_str(), hash_str.length(), hash_base64);
    Q_EMIT update_log_signal("hash: " + QString::fromStdString(hash_base64));

//    char* signed_data_decode = new char[1024];
//    base64_decode(signed_data_.c_str(), signed_data_.length(),signed_data_decode);
//    Q_EMIT update_log_signal("len: " + QString::number(strlen(signed_data_decode)));

    //计算签名，前三个参数传入SHA1对应的参数
//    iRet = RSA_verify(NID_sha256, (const unsigned char*)hash_base64,
//                      strlen(hash_base64),
//                      (const unsigned char*)(signed_data_decode),
//                      strlen(signed_data_decode), rsa_pub_key);
//    iRet = RSA_verify(NID_sha256, (const unsigned char*)hash_base64,
//                      strlen(hash_base64),
//                      (const unsigned char*)(signed_data_.c_str()),
//                      signed_data_.length(), rsa_pub_key);
    iRet = RSA_verify(NID_sha256, (const unsigned char*)hash_base64,
                      strlen(hash_base64),signed_data,
                      strlen((char*)signed_data), rsa_pub_key);
    if(1 != iRet) {
        Q_EMIT update_log_signal("verify error");
        unsigned long ulErr = ERR_get_error();
        char szErrMsg[1024] = {0};
        char *pTmp = NULL;
        pTmp = ERR_error_string(ulErr,szErrMsg); // 格式：error:errId:库:函数:原因
        Q_EMIT update_log_signal("pTmp: " + QString::fromStdString(pTmp));

        RSA_free(rsa_pub_key);
        return;
    }
    Q_EMIT update_log_signal("RSA_verify ok");

    RSA_free(rsa_pub_key);
}



int MainWindow::base64_encode(const char *in_str, int in_len, char *out_str) {
    BIO * bmem = NULL;
    BIO * b64 = NULL;
    BUF_MEM * bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
//    if(!with_new_line) {
//        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, in_str, in_len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char * buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    int size =bptr->length;

    memcpy(out_str, buff, strlen(buff));
    free(buff);

    BIO_free_all(b64);

    return size;
}

int MainWindow::base64_decode(const char *in_str, int in_len, char *out_str) {
    BIO * b64 = NULL;
    BIO * bmem = NULL;
    char * buffer = (char *)malloc(in_len);
    memset(buffer, 0, in_len);

    b64 = BIO_new(BIO_f_base64());
//    if(!with_new_line) {
//        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(in_str, in_len);
    bmem = BIO_push(b64, bmem);
    int size = BIO_read(bmem, buffer, in_len);

    memcpy(out_str, buffer, strlen(buffer));
    free(buffer);

    BIO_free_all(bmem);

    return size;
}

void MainWindow::base64_test_slot() {
    char instr[] = "hello";
    char outstr1[1024] = {0};
    base64_encode(instr,5,outstr1);
    Q_EMIT update_log_signal("base64 encode: " + QString::fromStdString(outstr1));

    char outstr2[1024] = {0};
    base64_decode(outstr1,strlen(outstr1),outstr2);
    Q_EMIT update_log_signal("base64 decode: " + QString::fromStdString(outstr2));
}
