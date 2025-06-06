#include "crypto_guard_ctx.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <memory>
#include <vector>
#include <array>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace CryptoGuard {

static std::string GetOpenSSLError() {
    unsigned long err = ERR_get_error();
    std::string buf(256, '\0');
    ERR_error_string_n(err, buf.data(), buf.size());
    return buf;
}

class CryptoGuardCtx::Impl {
    public:
    Impl() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    ~Impl() {
        EVP_cleanup();
        ERR_free_strings();
    }

    struct AesCipherParams {
        std::array<unsigned char, 32> key{};
        std::array<unsigned char, 16> iv{};
    };

    static AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
        std::array<unsigned char, 8> salt{};
        std::array<unsigned char, 48> out{};

        if (1 != PKCS5_PBKDF2_HMAC(
                password.data(), int(password.size()),
                salt.data(), salt.size(),
                10000,
                EVP_sha256(),
                int(out.size()), out.data()))
        {
            throw std::runtime_error("PBKDF2 failed: " + GetOpenSSLError());
        }

        AesCipherParams p;
        std::copy_n(out.data(), p.key.size(), p.key.begin());
        std::copy_n(out.data() + p.key.size(), p.iv.size(), p.iv.begin());
        return p;
    }

    void ProcessFile(std::istream &inStream, std::ostream &outStream,
                     std::string_view password, CipherMode mode) {
      if (!inStream.good())
        throw std::runtime_error("Bad input stream");
      if (!outStream.good())
        throw std::runtime_error("Bad output stream");

      AesCipherParams params = CreateCipherParamsFromPassword(password);

      std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx{
          EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

      if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

      const EVP_CIPHER *cipher = EVP_aes_256_cbc();
      int init_ok =
          (mode == CipherMode::Encrypt)
              ? EVP_EncryptInit_ex(ctx.get(), cipher, nullptr,
                                   params.key.data(), params.iv.data())
              : EVP_DecryptInit_ex(ctx.get(), cipher, nullptr,
                                   params.key.data(), params.iv.data());

      if (1 != init_ok)
        throw std::runtime_error("CipherInit failed: " + GetOpenSSLError());

      const size_t BUF_SZ = 4096;
      std::vector<unsigned char> inBuf(BUF_SZ);
      std::vector<unsigned char> outBuf(BUF_SZ + EVP_CIPHER_block_size(cipher));
      int outLen = 0;

      while (inStream.good()) {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), BUF_SZ);
        if (inStream.bad()) {
            throw std::runtime_error("I/O error while reading from input stream");
        }
        std::streamsize read = inStream.gcount();
        if (read > 0) {
          int update_ok =
              (mode == CipherMode::Encrypt)
                  ? EVP_EncryptUpdate(ctx.get(), outBuf.data(), &outLen,
                                      inBuf.data(), int(read))
                  : EVP_DecryptUpdate(ctx.get(), outBuf.data(), &outLen,
                                      inBuf.data(), int(read));

          if (1 != update_ok)
            throw std::runtime_error("CipherUpdate failed: " +
                                     GetOpenSSLError());

          outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
          if (!outStream.good())
            throw std::runtime_error("Write error during processing");
        }
      }

      int final_ok =
          (mode == CipherMode::Encrypt)
              ? EVP_EncryptFinal_ex(ctx.get(), outBuf.data(), &outLen)
              : EVP_DecryptFinal_ex(ctx.get(), outBuf.data(), &outLen);

      if (1 != final_ok)
        throw std::runtime_error("CipherFinal failed: " + GetOpenSSLError());

      outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
      if (!outStream.good())
        throw std::runtime_error("Write error finalizing processing");
    }

    std::string CalculateChecksum(std::istream& inStream) {
        if (!inStream.good()) throw std::runtime_error("Bad input stream");

        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
            mdctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
        if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");

        if (1 != EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr)) {
            throw std::runtime_error("DigestInit failed: " + GetOpenSSLError());
        }

        const size_t BUF_SZ = 4096;
        std::vector<unsigned char> buf(BUF_SZ);

        while (inStream.good()) {
            inStream.read(reinterpret_cast<char*>(buf.data()), BUF_SZ);
            if (inStream.bad()) {
                throw std::runtime_error("I/O error while reading from input stream");
            }
            std::streamsize read = inStream.gcount();
            if (read > 0) {
                if (1 != EVP_DigestUpdate(mdctx.get(), buf.data(), size_t(read))) {
                    throw std::runtime_error("DigestUpdate failed: " + GetOpenSSLError());
                }
            }
        }

        std::array<unsigned char,  EVP_MAX_MD_SIZE> hash{};
        unsigned int hashLen = 0;
        if (1 != EVP_DigestFinal_ex(mdctx.get(), hash.data(), &hashLen)) {
            throw std::runtime_error("DigestFinal failed: " + GetOpenSSLError());
        }

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < hashLen; ++i) {
            oss << std::setw(2) << int(hash[i]);
        }
        return oss.str();
    }
};

CryptoGuardCtx::CryptoGuardCtx()
  : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->ProcessFile(inStream, outStream, password, CipherMode::Encrypt);
}

void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->ProcessFile(inStream, outStream, password, CipherMode::Decrypt);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) {
    return pImpl_->CalculateChecksum(inStream);
}

} // namespace CryptoGuard
