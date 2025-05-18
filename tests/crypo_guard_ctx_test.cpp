#include <gtest/gtest.h>
#include <boost/program_options.hpp>
#include "cmd_options.h"

using namespace CryptoGuard;
namespace po = boost::program_options;

TEST(ProgramOptions, ParseEncryptSuccess) {
    const char* argv[] = {
      "prog",
      "--command",  "encrypt",
      "--input",    "in.txt",
      "--output",   "out.txt",
      "--password", "secret"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_NO_THROW({
        bool ok = opts.Parse(argc, const_cast<char**>(argv));
        EXPECT_TRUE(ok);
        EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
        EXPECT_EQ(opts.GetInputFile(),  "in.txt");
        EXPECT_EQ(opts.GetOutputFile(), "out.txt");
        EXPECT_EQ(opts.GetPassword(),   "secret");
    });
}

TEST(ProgramOptions, ParseDecryptCaseInsensitive) {
    const char* argv[] = {
      "prog",
      "--command",  "DECRYPT",
      "--input",    "input.bin",
      "--output",   "output.bin",
      "--password", "p@ss"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_NO_THROW({
        bool ok = opts.Parse(argc, const_cast<char**>(argv));
        EXPECT_TRUE(ok);
        EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    });
}

TEST(ProgramOptions, ParseChecksumOnlyInput) {
    const char* argv[] = {
      "prog",
      "--command", "checksum",
      "--input",   "file.dat"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_NO_THROW({
        bool ok = opts.Parse(argc, const_cast<char**>(argv));
        EXPECT_TRUE(ok);
        EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
        EXPECT_EQ(opts.GetOutputFile(), "");
        EXPECT_EQ(opts.GetPassword(),   "");
    });
}

TEST(ProgramOptions, MissingInputThrows) {
    const char* argv[] = {
      "prog",
      "--command", "checksum"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_THROW(opts.Parse(argc, const_cast<char**>(argv)), po::required_option);
}

TEST(ProgramOptions, UnknownCommandThrows) {
    const char* argv[] = {
      "prog",
      "--command", "encode",
      "--input",   "in.txt"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_THROW(opts.Parse(argc, const_cast<char**>(argv)), po::validation_error);
}

TEST(ProgramOptions, EncryptMissingPasswordThrows) {
    const char* argv[] = {
      "prog",
      "--command", "encrypt",
      "--input",   "in.txt",
      "--output",  "out.txt"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_THROW(opts.Parse(argc, const_cast<char**>(argv)), std::runtime_error);
}

TEST(ProgramOptions, DecryptMissingOutputThrows) {
    const char* argv[] = {
      "prog",
      "--command", "decrypt",
      "--input",   "in.txt",
      "--password","secret"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_THROW(opts.Parse(argc, const_cast<char**>(argv)), std::runtime_error);
}

TEST(ProgramOptions, HelpReturnsFalseNoThrow) {
    const char* argv[] = {
      "prog",
      "--help"
    };
    int argc = int(std::size(argv));

    ProgramOptions opts;
    EXPECT_NO_THROW({
        bool ok = opts.Parse(argc, const_cast<char**>(argv));
        EXPECT_FALSE(ok);
    });
}