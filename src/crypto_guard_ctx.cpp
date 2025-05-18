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
    char buf[256] = {0};
    ERR_error_string_n(err, buf, sizeof(buf));
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
        unsigned char salt[8] = {0};
        std::array<unsigned char, 48> out{};

        if (1 != PKCS5_PBKDF2_HMAC(
                password.data(), int(password.size()),
                salt, sizeof(salt),
                10000,
                EVP_sha256(),
                int(out.size()), out.data()))
        {
            throw std::runtime_error("PBKDF2 failed: " + GetOpenSSLError());
        }

        AesCipherParams p;
        std::copy_n(out.data(), 32, p.key.begin());
        std::copy_n(out.data() + 32, 16, p.iv.begin());
        return p;
    }

    void EncryptFile(std::istream& inStream,
                     std::ostream& outStream,
                     std::string_view password)
    {
        if (!inStream.good())  throw std::runtime_error("Bad input stream");
        if (!outStream.good()) throw std::runtime_error("Bad output stream");

        AesCipherParams params = CreateCipherParamsFromPassword(password);

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
            ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

            if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        if (1 != EVP_EncryptInit_ex(ctx.get(),
                                    EVP_aes_256_cbc(),
                                    nullptr,
                                    params.key.data(),
                                    params.iv.data()))
        {
            throw std::runtime_error("EncryptInit failed: " + GetOpenSSLError());
        }

        const size_t BUF_SZ = 4096;
        std::vector<unsigned char> inBuf(BUF_SZ);
        std::vector<unsigned char> outBuf(BUF_SZ + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int outLen = 0;

        while (inStream.good()) {
            inStream.read(reinterpret_cast<char*>(inBuf.data()), BUF_SZ);
            std::streamsize read = inStream.gcount();
            if (read > 0) {
                if (1 != EVP_EncryptUpdate(ctx.get(),
                                           outBuf.data(), &outLen,
                                           inBuf.data(), int(read)))
                {
                    throw std::runtime_error("EncryptUpdate failed: " + GetOpenSSLError());
                }
                outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
                if (!outStream.good())
                    throw std::runtime_error("Write error during encryption");
            }
        }

        if (1 != EVP_EncryptFinal_ex(ctx.get(),
                                     outBuf.data(), &outLen))
        {
            throw std::runtime_error("EncryptFinal failed: " + GetOpenSSLError());
        }
        outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
        if (!outStream.good())
            throw std::runtime_error("Write error finalizing encryption");
    }

    void DecryptFile(std::istream& inStream,
                     std::ostream& outStream,
                     std::string_view password)
    {
        if (!inStream.good())  throw std::runtime_error("Bad input stream");
        if (!outStream.good()) throw std::runtime_error("Bad output stream");

        AesCipherParams params = CreateCipherParamsFromPassword(password);

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
            ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};

        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        if (1 != EVP_DecryptInit_ex(ctx.get(),
                                    EVP_aes_256_cbc(),
                                    nullptr,
                                    params.key.data(),
                                    params.iv.data()))
        {
            throw std::runtime_error("DecryptInit failed: " + GetOpenSSLError());
        }

        const size_t BUF_SZ = 4096;
        std::vector<unsigned char> inBuf(BUF_SZ);
        std::vector<unsigned char> outBuf(BUF_SZ + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int outLen = 0;

        while (inStream.good()) {
            inStream.read(reinterpret_cast<char*>(inBuf.data()), BUF_SZ);
            std::streamsize read = inStream.gcount();
            if (read > 0) {
                if (1 != EVP_DecryptUpdate(ctx.get(),
                                           outBuf.data(), &outLen,
                                           inBuf.data(), int(read)))
                {
                    throw std::runtime_error("DecryptUpdate failed: " + GetOpenSSLError());
                }
                outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
                if (!outStream.good())
                    throw std::runtime_error("Write error during decryption");
            }
        }

        if (1 != EVP_DecryptFinal_ex(ctx.get(),
                                     outBuf.data(), &outLen))
        {
            throw std::runtime_error("DecryptFinal failed: " + GetOpenSSLError());
        }
        outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
        if (!outStream.good())
            throw std::runtime_error("Write error finalizing decryption");
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
            std::streamsize read = inStream.gcount();
            if (read > 0) {
                if (1 != EVP_DigestUpdate(mdctx.get(), buf.data(), size_t(read))) {
                    throw std::runtime_error("DigestUpdate failed: " + GetOpenSSLError());
                }
            }
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;
        if (1 != EVP_DigestFinal_ex(mdctx.get(), hash, &hashLen)) {
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
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) {
    return pImpl_->CalculateChecksum(inStream);
}

} // namespace CryptoGuard
