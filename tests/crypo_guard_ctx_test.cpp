#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string>

using CryptoGuard::CryptoGuardCtx;

namespace {

std::string Encrypt(CryptoGuardCtx &ctx, const std::string &data, std::string_view password) {
    std::stringstream in{data};
    std::stringstream out;
    ctx.EncryptFile(in, out, password);
    return out.str();
}

std::string Decrypt(CryptoGuardCtx &ctx, const std::string &data, std::string_view password) {
    std::stringstream in{data};
    std::stringstream out;
    ctx.DecryptFile(in, out, password);
    return out.str();
}

}  // namespace

TEST(CryptoGuardCtx, EncryptPadsToBlockSize) {
    CryptoGuardCtx ctx;
    const std::string data(15, 'a');

    const auto encrypted = Encrypt(ctx, data, "1234");

    EXPECT_NE(encrypted, data);
    EXPECT_EQ(encrypted.size(), 16u);
}

TEST(CryptoGuardCtx, EncryptDependsOnPassword) {
    CryptoGuardCtx ctx;
    EXPECT_EQ(Encrypt(ctx, "hello", "1234"), Encrypt(ctx, "hello", "1234"));
    EXPECT_NE(Encrypt(ctx, "hello", "1234"), Encrypt(ctx, "hello", "4321"));
}

TEST(CryptoGuardCtx, EncryptBadInputStreamThrows) {
    CryptoGuardCtx ctx;
    std::stringstream in{"data"};
    std::stringstream out;
    in.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.EncryptFile(in, out, "1234"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptRestoresData) {
    CryptoGuardCtx ctx;
    const std::string data = "01234567890123456789";

    EXPECT_EQ(Decrypt(ctx, Encrypt(ctx, data, "1234"), "1234"), data);
}

TEST(CryptoGuardCtx, DecryptWrongPasswordThrows) {
    CryptoGuardCtx ctx;
    const auto encrypted = Encrypt(ctx, "secret data", "right");

    ASSERT_THROW(Decrypt(ctx, encrypted, "wrong"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptTruncatedDataThrows) {
    CryptoGuardCtx ctx;
    auto encrypted = Encrypt(ctx, "secret data", "1234");
    encrypted.pop_back();

    ASSERT_THROW(Decrypt(ctx, encrypted, "1234"), std::runtime_error);
}

TEST(CryptoGuardCtx, ChecksumKnownString) {
    CryptoGuardCtx ctx;
    std::stringstream in{"abc"};
    EXPECT_EQ(ctx.CalculateChecksum(in), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(CryptoGuardCtx, ChecksumEmptyInput) {
    CryptoGuardCtx ctx;
    std::stringstream in;
    EXPECT_EQ(ctx.CalculateChecksum(in), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(CryptoGuardCtx, ChecksumBadInputStreamThrows) {
    CryptoGuardCtx ctx;
    std::stringstream in{"data"};
    in.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.CalculateChecksum(in), std::runtime_error);
}

TEST(CryptoGuardCtx, RoundTripKeepsChecksum) {
    CryptoGuardCtx ctx;
    const std::string original(10'000, 'x');
    std::stringstream originalStream{original};
    const auto checksumBefore = ctx.CalculateChecksum(originalStream);

    const auto decrypted = Decrypt(ctx, Encrypt(ctx, original, "1234"), "1234");
    std::stringstream decryptedStream{decrypted};

    EXPECT_EQ(decrypted, original);
    EXPECT_EQ(ctx.CalculateChecksum(decryptedStream), checksumBefore);
}
