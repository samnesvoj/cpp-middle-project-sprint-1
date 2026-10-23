#include "cmd_options.h"

#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using CryptoGuard::ProgramOptions;
using COMMAND_TYPE = ProgramOptions::COMMAND_TYPE;

void ParseArgs(ProgramOptions &options, std::vector<std::string> args) {
    args.insert(args.begin(), "CryptoGuard");
    std::vector<char *> argv;
    for (auto &arg : args) {
        argv.push_back(arg.data());
    }
    argv.push_back(nullptr);
    options.Parse(static_cast<int>(args.size()), argv.data());
}

}  // namespace

TEST(ProgramOptions, ValidEncrypt) {
    ProgramOptions options;
    ParseArgs(options, {"--command", "encrypt", "--input", "in.txt", "--output", "out.txt", "--password", "1234"});

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_EQ(options.GetOutputFile(), "out.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

TEST(ProgramOptions, ValidDecrypt) {
    ProgramOptions options;
    ParseArgs(options, {"-i", "enc.txt", "-o", "dec.txt", "-p", "1234", "--command", "decrypt"});

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "enc.txt");
    EXPECT_EQ(options.GetOutputFile(), "dec.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

TEST(ProgramOptions, ValidChecksum) {
    ProgramOptions options;
    ParseArgs(options, {"-i", "in.txt", "--command", "checksum"});

    EXPECT_EQ(options.GetCommand(), COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
}

TEST(ProgramOptions, UnknownCommandThrows) {
    ProgramOptions options;
    EXPECT_THROW(ParseArgs(options, {"--command", "compress", "-i", "in.txt"}), std::runtime_error);
}

TEST(ProgramOptions, MissingInputThrows) {
    ProgramOptions options;
    EXPECT_THROW(ParseArgs(options, {"--command", "checksum"}), std::runtime_error);
}

TEST(ProgramOptions, MissingPasswordThrows) {
    ProgramOptions options;
    EXPECT_THROW(ParseArgs(options, {"--command", "encrypt", "-i", "in.txt", "-o", "out.txt"}), std::runtime_error);
}

TEST(ProgramOptions, HelpSkipsValidation) {
    ProgramOptions options;
    EXPECT_NO_THROW(ParseArgs(options, {"--help"}));
    EXPECT_TRUE(options.IsHelpRequested());
}
