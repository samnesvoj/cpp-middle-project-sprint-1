#include "crypto_guard_ctx.h"

#include <array>
#include <format>
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>

namespace CryptoGuard {

namespace {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};

using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

struct MdCtxDeleter {
    void operator()(EVP_MD_CTX *ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};

using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

std::string OpenSSLError(std::string_view what) {
    const unsigned long code = ERR_get_error();
    ERR_clear_error();
    if (code == 0) {
        return std::string{what};
    }
    std::array<char, 256> buf{};
    ERR_error_string_n(code, buf.data(), buf.size());
    return std::format("{}: {}", what, buf.data());
}

}  // namespace

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ProcessStream(inStream, outStream, password, true);
    }
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        ProcessStream(inStream, outStream, password, false);
    }
    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream.good()) {
            throw std::runtime_error{"Input stream is not readable"};
        }

        MdCtxPtr ctx{EVP_MD_CTX_new()};
        if (!ctx) {
            throw std::runtime_error{OpenSSLError("Failed to create digest context")};
        }
        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error{OpenSSLError("Failed to initialize digest")};
        }

        std::array<char, BUFFER_SIZE> buf{};
        while (inStream) {
            inStream.read(buf.data(), buf.size());
            const auto readLen = static_cast<std::size_t>(inStream.gcount());
            if (inStream.bad()) {
                throw std::runtime_error{"Failed to read from input stream"};
            }
            if (readLen == 0) {
                break;
            }
            if (EVP_DigestUpdate(ctx.get(), buf.data(), readLen) != 1) {
                throw std::runtime_error{OpenSSLError("Failed to update digest")};
            }
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digestLen = 0;
        if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digestLen) != 1) {
            throw std::runtime_error{OpenSSLError("Failed to finalize digest")};
        }

        std::stringstream hex;
        hex << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < digestLen; ++i) {
            hex << std::setw(2) << static_cast<int>(digest[i]);
        }
        return hex.str();
    }

private:
    static constexpr std::size_t BUFFER_SIZE = 4096;

    static void ProcessStream(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                              bool encrypt) {
        if (!inStream.good()) {
            throw std::runtime_error{"Input stream is not readable"};
        }
        if (!outStream.good()) {
            throw std::runtime_error{"Output stream is not writable"};
        }

        AesCipherParams params = CreateChiperParamsFromPassword(password);
        params.encrypt = encrypt;

        CipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) {
            throw std::runtime_error{OpenSSLError("Failed to create cipher context")};
        }
        if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) !=
            1) {
            throw std::runtime_error{OpenSSLError("Failed to initialize cipher")};
        }

        std::array<unsigned char, BUFFER_SIZE> inBuf{};
        std::array<unsigned char, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH> outBuf{};
        int outLen = 0;

        auto writeOut = [&outStream, &outBuf](int len) {
            outStream.write(reinterpret_cast<const char *>(outBuf.data()), len);
            if (!outStream) {
                throw std::runtime_error{"Failed to write to output stream"};
            }
        };

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
            const auto readLen = static_cast<int>(inStream.gcount());
            if (inStream.bad()) {
                throw std::runtime_error{"Failed to read from input stream"};
            }
            if (readLen == 0) {
                break;
            }
            if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), readLen) != 1) {
                throw std::runtime_error{OpenSSLError("Failed to process data")};
            }
            writeOut(outLen);
        }

        if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) != 1) {
            throw std::runtime_error{
                OpenSSLError(encrypt ? "Failed to finalize encryption"
                                     : "Failed to finalize decryption (wrong password or corrupted data)")};
        }
        writeOut(outLen);
    }

    static AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()),
                                    static_cast<int>(password.size()), 1, params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;

CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
