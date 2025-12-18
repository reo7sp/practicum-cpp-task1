#include <array>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <unistd.h>

#include "crypto_guard_ctx.h"

namespace CryptoGuard {

class OpenSSLError : public std::runtime_error {
public:
    explicit OpenSSLError(const char *prefix, unsigned long errCode = ERR_get_error())
        : std::runtime_error(Format(prefix, errCode)) {}

private:
    static std::string Format(std::string_view prefix, unsigned long errCode) {
        if (!errCode)
            return std::string(prefix);

        std::array<char, 256> buf;
        ERR_error_string_n(errCode, buf.data(), buf.size());

        return std::format("{}: {}", prefix, std::string_view(buf.data()));
    }
};

enum class Command {
    Decrypt = 0,
    Encrypt = 1,
};

const size_t KEY_SIZE = 16;
const size_t IV_SIZE = 16;
const size_t BLOCK_SIZE = 1024;
const size_t SHA256_SIZE = 32;

struct AesCipherParams {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm
    std::array<unsigned char, KEY_SIZE> key;       // Encryption key
    std::array<unsigned char, IV_SIZE> iv;         // Initialization vector
};

AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int res = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                             reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                             params.key.data(), params.iv.data());
    if (!res)
        throw OpenSSLError("Failed to create a key from password");

    return params;
}

struct CryptoGuardCtx::Impl {
    void ProcessFile(Command command, std::istream& inStream, std::ostream& outStream, std::string_view password);
    std::string CalculateChecksum(std::istream& inStream);
};

void CryptoGuardCtx::Impl::ProcessFile(Command command, std::istream& inStream, std::ostream& outStream,
                                       std::string_view password) {
    if (!inStream.good())
        throw std::runtime_error("Cannot open the input file");
    if (!outStream.good())
        throw std::runtime_error("Cannot generate the output file");

    auto params = CreateChiperParamsFromPassword(password);

    using EVPCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX,
        decltype([](EVP_CIPHER_CTX* ctx) {
            EVP_CIPHER_CTX_free(ctx);
        })
    >;
    EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx.get())
        throw OpenSSLError("EVP_CIPHER_CTX_new failed");

    int res = EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                                static_cast<int>(command));
    if (!res)
        throw OpenSSLError("EVP_CipherInit_ex failed");

    std::array<unsigned char, BLOCK_SIZE> inBuffer;
    std::array<unsigned char, BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH> outBuffer;
    bool inHasData = false;
    int outBufferN = 0;

    while (!inStream.eof()) {
        inStream.read(reinterpret_cast<char*>(inBuffer.data()), BLOCK_SIZE);
        if (!inStream && !inStream.eof())
            throw std::runtime_error("read failed");

        auto inN = inStream.gcount();
        if (!inN)
            break;

        inHasData = true;

        int res = EVP_CipherUpdate(ctx.get(), outBuffer.data(), &outBufferN, inBuffer.data(), static_cast<int>(inN));
        if (!res)
            throw OpenSSLError("EVP_CipherUpdate failed");

        outStream.write(reinterpret_cast<char*>(outBuffer.data()), outBufferN);
        if (!outStream)
            throw std::runtime_error("write failed");
    }

    if (!inHasData && command == Command::Decrypt)
        return;

    res = EVP_CipherFinal_ex(ctx.get(), outBuffer.data(), &outBufferN);
    if (!res)
        throw OpenSSLError("EVP_CipherFinal_ex failed");

    outStream.write(reinterpret_cast<char*>(outBuffer.data()), outBufferN);
    if (!outStream)
        throw std::runtime_error("write failed");
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::istream& inStream) {
    if (!inStream.good())
        throw std::runtime_error("Cannot open the input file");

    using EVPMDCtxPtr = std::unique_ptr<EVP_MD_CTX,
        decltype([](EVP_MD_CTX* ctx) {
            EVP_MD_CTX_free(ctx);
        })
    >;
    EVPMDCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx.get())
        throw OpenSSLError("EVP_MD_CTX_new failed");

    int res = EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);
    if (!res)
        throw OpenSSLError("EVP_DigestInit_ex failed");

    std::array<unsigned char, BLOCK_SIZE> inBuffer;
    std::array<unsigned char, SHA256_SIZE> outBuffer;
    int outBufferN;

    while (!inStream.eof()) {
        inStream.read(reinterpret_cast<char*>(inBuffer.data()), BLOCK_SIZE);
        if (!inStream && !inStream.eof())
            throw std::runtime_error("read failed");

        auto inN = inStream.gcount();
        if (!inN)
            break;

        int res = EVP_DigestUpdate(ctx.get(), inBuffer.data(), inN);
        if (!res)
            throw OpenSSLError("EVP_DigestUpdate failed");
    }

    res = EVP_DigestFinal_ex(ctx.get(), outBuffer.data(), nullptr);
    if (!res)
        throw OpenSSLError("EVP_DigestFinal_ex failed");

    std::ostringstream outStr;
    outStr << std::hex << std::setfill('0');
    for (unsigned char b : outBuffer) {
        outStr << std::setw(2) << static_cast<unsigned int>(b);
    }

    return outStr.str();
}

CryptoGuardCtx::CryptoGuardCtx() : impl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx&&) noexcept = default;

CryptoGuardCtx& CryptoGuardCtx::operator=(CryptoGuardCtx&&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::istream& inStream, std::ostream& outStream, std::string_view password) {
    impl_->ProcessFile(Command::Encrypt, inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::istream& inStream, std::ostream& outStream, std::string_view password) {
    impl_->ProcessFile(Command::Decrypt, inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream& inStream) {
    return impl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
