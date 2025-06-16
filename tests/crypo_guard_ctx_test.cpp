#include <array>
#include <gtest/gtest.h>
#include <boost/program_options.hpp>
#include "cmd_options.h"
#include <crypto_guard_ctx.h>

using namespace CryptoGuard;
namespace po = boost::program_options;

TEST(ProgramOptions, ParseEncryptSuccess) {
    static constexpr std::array<const char*, 9> argv = {
      "prog",
      "--command",  "encrypt",
      "--input",    "in.txt",
      "--output",   "out.txt",
      "--password", "secret"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_NO_THROW({
        bool ok = opts.Parse(argc, const_cast<char**>(argv.data()));
        EXPECT_TRUE(ok);
    });
}

TEST(ProgramOptions, ParseDecryptCaseInsensitive) {
    static constexpr std::array<const char*, 9> argv = {
      "prog",
      "--command",  "DECRYPT",
      "--input",    "input.bin",
      "--output",   "output.bin",
      "--password", "p@ss"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_NO_THROW({
        bool ok = opts.Parse(argc, const_cast<char**>(argv.data()));
        EXPECT_TRUE(ok);
        EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    });
}

TEST(ProgramOptions, ParseChecksumOnlyInput) {
    static constexpr std::array<const char*, 5> argv = {
      "prog",
      "--command", "checksum",
      "--input",   "file.dat"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_NO_THROW({
        bool ok = opts.Parse(argc, const_cast<char**>(argv.data()));
        EXPECT_TRUE(ok);
        EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
        EXPECT_EQ(opts.GetOutputFile(), "");
        EXPECT_EQ(opts.GetPassword(),   "");
    });
}

TEST(ProgramOptions, MissingInputThrows) {
    static constexpr std::array<const char*, 3> argv = {
      "prog",
      "--command", "checksum"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_THROW(opts.Parse(argc, const_cast<char**>(argv.data())), po::required_option);
}

TEST(ProgramOptions, UnknownCommandThrows) {
    static constexpr std::array<const char*, 5> argv = {
      "prog",
      "--command", "encode",
      "--input",   "in.txt"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_THROW(opts.Parse(argc, const_cast<char**>(argv.data())), po::validation_error);
}

TEST(ProgramOptions, EncryptMissingPasswordThrows) {
    static constexpr std::array<const char*, 7> argv = {
      "prog",
      "--command", "encrypt",
      "--input",   "in.txt",
      "--output",  "out.txt"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_THROW(opts.Parse(argc, const_cast<char**>(argv.data())), std::runtime_error);
}

TEST(ProgramOptions, DecryptMissingOutputThrows) {
    static constexpr std::array<const char*, 7> argv = {
      "prog",
      "--command", "decrypt",
      "--input",   "in.txt",
      "--password","secret"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_THROW(opts.Parse(argc, const_cast<char**>(argv.data())), std::runtime_error);
}

TEST(ProgramOptions, HelpReturnsFalseNoThrow) {
    static constexpr std::array<const char*, 2> argv = {
      "prog",
      "--help"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_NO_THROW({
        bool ok = opts.Parse(argc, const_cast<char**>(argv.data()));
        EXPECT_FALSE(ok);
    });
}

class CryptoGuardCtxTest : public ::testing::Test {
protected:
    CryptoGuardCtx ctx;
    const std::string password  = "testpassword";
    const std::string plaintext = "Hello OpenSSL crypto world!";
};


TEST_F(CryptoGuardCtxTest, EncryptProducesNonEmptyCiphertext) {
    std::stringstream in(plaintext), out;
    ASSERT_NO_THROW(ctx.EncryptFile(in, out, password));
    EXPECT_FALSE(out.str().empty());
    EXPECT_NE(out.str(), plaintext);
}

TEST_F(CryptoGuardCtxTest, EncryptBadInputThrows) {
    std::stringstream in(plaintext), out;
    in.setstate(std::ios::badbit);
    EXPECT_THROW(ctx.EncryptFile(in, out, password), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, EncryptBadOutputThrows) {
    std::stringstream in(plaintext), out;
    out.setstate(std::ios::badbit);
    EXPECT_THROW(ctx.EncryptFile(in, out, password), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, EncryptThenDecryptRestoresPlaintext) {
    std::stringstream in(plaintext), cipher;
    ctx.EncryptFile(in, cipher, password);

    std::stringstream cipher_in(cipher.str()), decrypted;
    ASSERT_NO_THROW(ctx.DecryptFile(cipher_in, decrypted, password));
    EXPECT_EQ(decrypted.str(), plaintext);
}

TEST_F(CryptoGuardCtxTest, DecryptWithWrongPasswordThrows) {
    std::stringstream in(plaintext), cipher;
    ctx.EncryptFile(in, cipher, password);

    std::stringstream cipher_in(cipher.str()), decrypted;
    EXPECT_THROW(ctx.DecryptFile(cipher_in, decrypted, "wrongpass"), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, DecryptBadInputThrows) {
    std::stringstream in(plaintext), cipher;
    ctx.EncryptFile(in, cipher, password);

    std::stringstream cipher_in(cipher.str()), decrypted;
    cipher_in.setstate(std::ios::failbit);
    EXPECT_THROW(ctx.DecryptFile(cipher_in, decrypted, password), std::runtime_error);
}

static constexpr std::string_view SHA256_EMPTY =
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855";

static constexpr std::string_view SHA256_ABC =
    "ba7816bf8f01cfea414140de5dae2223"
    "b00361a396177a9cb410ff61f20015ad";

TEST_F(CryptoGuardCtxTest, ChecksumEmptyStream) {
    std::stringstream in;
    EXPECT_EQ(ctx.CalculateChecksum(in), SHA256_EMPTY);
}

TEST_F(CryptoGuardCtxTest, ChecksumKnownString) {
    std::stringstream in("abc");
    EXPECT_EQ(ctx.CalculateChecksum(in), SHA256_ABC);
}

TEST_F(CryptoGuardCtxTest, ChecksumBadStreamThrows) {
    std::stringstream in;
    in.setstate(std::ios::badbit);
    EXPECT_THROW(ctx.CalculateChecksum(in), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, ChecksumMatchesBeforeAndAfterEncryption) {
    std::stringstream in0(plaintext);
    std::string sum0 = ctx.CalculateChecksum(in0);

    std::stringstream in1(plaintext), cipher;
    ctx.EncryptFile(in1, cipher, password);

    std::stringstream cipher_in(cipher.str()), decrypted;
    ctx.DecryptFile(cipher_in, decrypted, password);

    std::stringstream in2(decrypted.str());
    std::string sum2 = ctx.CalculateChecksum(in2);

    EXPECT_EQ(sum2, sum0);
}