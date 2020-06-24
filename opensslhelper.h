#ifndef OPENSSLHELPER_H
#define OPENSSLHELPER_H

#include <string>

namespace openssl {
class OpensslHelper {
 public:
  enum HashType { HASHTYPE_SHA1, HASHTYPE_SHA256 };

  explicit OpensslHelper();

  void GeneratePairkeyRSA();

  std::string Hash(const std::string& indata, HashType type);
  std::string Sign(const std::string& prikey, const std::string& indata,
                   int type);
  int Verify(const std::string& pubkey, const std::string& indata,
             const std::string& signed_data, int type);

  std::string EncodeBase64(const std::string& data, bool with_new_line);
  std::string DecodeBase64(const std::string& data, bool with_new_line);

  std::string AesEncrypt(const std::string& indata,
                         const std::string& iv);
  std::string AesDecrypt(const std::string& indata,
                         const std::string& iv);

 private:
  const int kKeyLen = 1024;                      // 密钥长度
  const std::string kPubkeyFile = "pubkey.pem";  // 公钥路径
  const std::string kPrikeyFile = "prikey.pem";  // 私钥路径

  const std::string kAesKey = "1234567890abcdef";

};  // class OpensslHelper
}  // namespace openssl

#endif  // OPENSSLHELPER_H
