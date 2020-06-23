#include "opensslhelper.h"

#include <assert.h>
#include <string.h>

#include <iostream>

#include "openssl/rsa.h"
#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/pem.h"
#include "openssl/err.h"

namespace openssl {

RSA* GetPublicKeyRSA(std::string str_pubkey);

OpensslHelper::OpensslHelper() {}

void OpensslHelper::GeneratePairkeyRSA() {
  // 公私密钥对
  size_t pri_len = 0;
  size_t pub_len = 0;
  char* pri_key = NULL;
  char* pub_key = NULL;

  // 生成密钥对
  RSA* keypair = RSA_new();
  BIGNUM* bignum = BN_new();
  int ret = BN_set_word(bignum, RSA_F4);  // another "RSA_3"
  ret = RSA_generate_key_ex(keypair, kKeyLen, bignum, NULL);
  BN_free(bignum);
  if (ret != 1) {
    std::cout << "RSA_generate_key_ex Failed" << std::endl;
    return;
    // FAILED
  }

  BIO* pri = BIO_new(BIO_s_mem());
  BIO* pub = BIO_new(BIO_s_mem());

  PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
  PEM_write_bio_RSAPublicKey(pub, keypair);

  // 获取长度
  pri_len = BIO_pending(pri);
  pub_len = BIO_pending(pub);

  // 密钥对读取到字符串
  pri_key = (char*)malloc(pri_len + 1);
  pub_key = (char*)malloc(pub_len + 1);

  BIO_read(pri, pri_key, pri_len);
  BIO_read(pub, pub_key, pub_len);

  pri_key[pri_len] = '\0';
  pub_key[pub_len] = '\0';

  std::string strKey[2];
  // 存储密钥对
  strKey[0] = pub_key;
  strKey[1] = pri_key;

  std::cout << "pub_key len: \n" << strKey[0].length() << std::endl;
  std::cout << "pri_key len: \n" << strKey[1].length() << std::endl;
  std::string encode_pub_key = EncodeBase64(strKey[0], false);
  std::string encode_pri_key = EncodeBase64(strKey[1], false);

  std::cout << "encode_pub_key: \n" << encode_pub_key << std::endl;
  std::cout << "encode_pri_key: \n" << encode_pri_key << std::endl;

  std::cout << "encode_pub_key len: " << encode_pub_key.length() << std::endl;
  std::cout << "encode_pri_key len: " << encode_pri_key.length() << std::endl;

  std::cout << "decode_pub_key: \n" << DecodeBase64(encode_pub_key, false)
            << std::endl;
  std::cout << "decode_pri_key: \n" << DecodeBase64(encode_pri_key, false)
            << std::endl;

  //    // 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private
  //    key开头的）
  //    FILE *pubFile = fopen(kPubkeyFile.c_str(), "w");
  //    if (pubFile == NULL) {
  //        assert(false);
  //        return;
  //    }
  //    fputs(pub_key, pubFile);
  //    fclose(pubFile);

  //    FILE *priFile = fopen(kPrikeyFile.c_str(), "w");
  //    if (priFile == NULL) {
  //        assert(false);
  //        return;
  //    }
  //    fputs(pri_key, priFile);
  //    fclose(priFile);

  // 内存释放
  RSA_free(keypair);
  BIO_free_all(pub);
  BIO_free_all(pri);

  free(pri_key);
  free(pub_key);
}

std::string OpensslHelper::Hash(const std::string& indata, HashType type) {
  std::string hash_str("");
  unsigned char uchash[256] = {0};  //计算的摘要
  switch (type) {
    case HashType::HASHTYPE_SHA1:
      SHA1((const unsigned char*)indata.c_str(), indata.length(), uchash);
      hash_str = (char*)uchash;
      break;
    case HashType::HASHTYPE_SHA256:
      SHA256((const unsigned char*)indata.c_str(), indata.length(), uchash);
      hash_str = (char*)uchash;
      break;
    default:
      break;
  }

  return hash_str;
}

std::string OpensslHelper::Sign(const std::string& prikey,
                                const std::string& indata, int type) {
  unsigned char signed_data[2048] = {0};
  unsigned int siglen = 0;
  //计算签名，前三个参数传入SHA256对应的参数
  //    int ret = RSA_sign(type, (const unsigned char*)indata.c_str(),
  //                    indata.length(), signed_data, &siglen, rsa_pri_key);
  //    if(1 != ret) {
  //        return "";
  //    }

  std::string signed_str((char*)signed_data);
  return signed_str;
}

int OpensslHelper::Verify(const std::string& pubkey, const std::string& indata,
                          const std::string& signed_data, int type) {
  return 0;
}

std::string OpensslHelper::EncodeBase64(const std::string& data,
                                        bool with_new_line) {
  BIO* bmem = NULL;
  BIO* b64 = NULL;
  BUF_MEM* bptr = NULL;

  b64 = BIO_new(BIO_f_base64());
  if (!with_new_line) {
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, data.c_str(), data.length());
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  BIO_free_all(b64);

  char* buff = new char[bptr->length + 1];
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = 0;

  std::string encode_data(buff);
  delete[] buff;
  return encode_data;
}

std::string OpensslHelper::DecodeBase64(const std::string& data,
                                        bool with_new_line) {
  BIO* b64 = NULL;
  BIO* bmem = NULL;
  char* buffer = new char[data.length() + 1];
  memset(buffer, 0, data.length());

  b64 = BIO_new(BIO_f_base64());
  if (!with_new_line) {
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }
  bmem = BIO_new_mem_buf(data.c_str(), data.length());
  bmem = BIO_push(b64, bmem);
  BIO_read(bmem, buffer, data.length());
  BIO_free_all(bmem);

  std::string decode_data(buffer);
  delete[] buffer;
  return decode_data;
}

////得到公钥的RSA结构体
// RSA* GetPublicKeyRSA(std::string str_pubkey) {
//    int size = str_pubkey.size();
//    for(int i = 64; i != size; ++i) {
//        if(str_pubkey[i] != '\n') {
//            str_pubkey.insert(i, "\n");
//        }
//        i++;
//    }
//    strPublicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
//    strPublicKey.append("\n-----END PUBLIC KEY-----\n");

//    BIO *bio = NULL;
//    RSA *rsa = NULL;
//    char *chPublicKey = const_cast<char *>(str_pubkey.c_str());
//    if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)
//    //从字符串读取RSA公钥
//    {
//        cout<< "error,chPublicKey:"<< chPublicKey << endl;
//    }
//    rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
//    //从bio结构中得到rsa结构
//    if (NULL == rsa)
//    {
//        BIO_free_all(bio);
//        unsigned long ulErr = ERR_get_error(); // 获取错误号
//        char szErrMsg[1024] = {0};
//        char *pTmp = NULL;
//        pTmp = ERR_error_string(ulErr,szErrMsg); //
//        格式：error:errId:库:函数:原因
//        cout << szErrMsg << endl;
//    }
//    return rsa;
//}

}  // namespace openssl
