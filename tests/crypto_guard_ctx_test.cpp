#include "crypto_guard_ctx.h"

#include <sstream>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

TEST(CryptoGuardCtxEncrypt, EncryptsNonEmptyStream) {
    CryptoGuard::CryptoGuardCtx ctx;

    const std::string plain_text = "Hello, CryptoGuard! This is a test.";
    std::stringstream in(plain_text);
    std::stringstream out;

    EXPECT_NO_THROW(ctx.EncryptFile(in, out, "password"));

    const std::string cipher_text = out.str();
    EXPECT_FALSE(cipher_text.empty());
    EXPECT_NE(cipher_text, plain_text);
}

TEST(CryptoGuardCtxEncrypt, EncryptsEmptyStreamDoesNotThrow) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream in;
    std::stringstream out;

    EXPECT_NO_THROW(ctx.EncryptFile(in, out, "password"));
}

TEST(CryptoGuardCtxEncrypt, EncryptFailsOnBadOutputStream) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream in("data");
    std::stringstream out;
    out.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.EncryptFile(in, out, "password"), std::runtime_error);
}

TEST(CryptoGuardCtxDecrypt, DecryptRestoresOriginalText) {
    CryptoGuard::CryptoGuardCtx ctx;

    const std::string plain_text = "The quick brown fox jumps over the lazy dog.";
    std::stringstream in(plain_text);
    std::stringstream encrypted;

    ASSERT_NO_THROW(ctx.EncryptFile(in, encrypted, "password"));

    std::stringstream encrypted_copy(encrypted.str());
    std::stringstream decrypted;

    EXPECT_NO_THROW(ctx.DecryptFile(encrypted_copy, decrypted, "password"));
    EXPECT_EQ(decrypted.str(), plain_text);
}

TEST(CryptoGuardCtxDecrypt, DecryptWithWrongPasswordThrows) {
    CryptoGuard::CryptoGuardCtx ctx;

    const std::string plain_text = "Another piece of text to encrypt.";
    std::stringstream in(plain_text);
    std::stringstream encrypted;

    ASSERT_NO_THROW(ctx.EncryptFile(in, encrypted, "correct_password"));

    std::stringstream encrypted_copy(encrypted.str());
    std::stringstream decrypted;

    ASSERT_THROW(ctx.DecryptFile(encrypted_copy, decrypted, "wrong_password"), std::runtime_error);
}

TEST(CryptoGuardCtxDecrypt, DecryptEmptyStreamDoesNotThrow) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream in;
    std::stringstream out;

    EXPECT_NO_THROW(ctx.DecryptFile(in, out, "password"));
}

TEST(CryptoGuardCtxChecksum, SameInputSameChecksum) {
    CryptoGuard::CryptoGuardCtx ctx;

    const std::string data = "checksum test data";
    std::stringstream in1(data);
    std::stringstream in2(data);

    std::string checksum1;
    std::string checksum2;

    ASSERT_NO_THROW(checksum1 = ctx.CalculateChecksum(in1));
    ASSERT_NO_THROW(checksum2 = ctx.CalculateChecksum(in2));

    EXPECT_FALSE(checksum1.empty());
    EXPECT_EQ(checksum1, checksum2);
}

TEST(CryptoGuardCtxChecksum, DifferentInputDifferentChecksum) {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream in1("first data");
    std::stringstream in2("second data");

    std::string checksum1;
    std::string checksum2;

    ASSERT_NO_THROW(checksum1 = ctx.CalculateChecksum(in1));
    ASSERT_NO_THROW(checksum2 = ctx.CalculateChecksum(in2));

    EXPECT_NE(checksum1, checksum2);
}
