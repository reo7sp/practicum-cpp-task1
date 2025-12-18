#pragma once

#include <experimental/propagate_const>
#include <memory>
#include <string>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();
    CryptoGuardCtx(const CryptoGuardCtx&) = delete;
    CryptoGuardCtx& operator=(const CryptoGuardCtx&) = delete;
    CryptoGuardCtx(CryptoGuardCtx&&) noexcept;
    CryptoGuardCtx& operator=(CryptoGuardCtx&&) noexcept;

    void EncryptFile(std::istream& inStream, std::ostream& outStream, std::string_view password);
    void DecryptFile(std::istream& inStream, std::ostream& outStream, std::string_view password);
    std::string CalculateChecksum(std::istream& inStream);

private:
    class Impl;
    std::experimental::propagate_const<std::unique_ptr<Impl>> impl_;
};

}  // namespace CryptoGuard
