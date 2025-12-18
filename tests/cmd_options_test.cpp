#include <cstddef>
#include <iterator>
#include <string>

#include <boost/program_options/errors.hpp>
#include <gtest/gtest.h>

#include "cmd_options.h"

TEST(ProgramOptions, EncryptCommandWithAllParameters) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "program", "--command", "encrypt",
        "--input", "input.txt",
        "--output", "output.txt",
        "--password", "secret123",
    };
    size_t argc = std::size(argv);

    EXPECT_NO_THROW(options.Parse(static_cast<int>(argc), const_cast<char**>(argv)));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "secret123");
}

TEST(ProgramOptions, DecryptCommandWithAllParameters) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "program", "--command", "decrypt",
        "--input", "encrypted.txt",
        "--output", "decrypted.txt",
        "--password", "mypassword",
    };
    size_t argc = std::size(argv);

    EXPECT_NO_THROW(options.Parse(static_cast<int>(argc), const_cast<char**>(argv)));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "encrypted.txt");
    EXPECT_EQ(options.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(options.GetPassword(), "mypassword");
}

TEST(ProgramOptions, ChecksumCommandWithAllParameters) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {
        "program", "--command", "checksum",
        "--input", "file.txt",
    };
    size_t argc = std::size(argv);

    EXPECT_NO_THROW(options.Parse(static_cast<int>(argc), const_cast<char**>(argv)));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "file.txt");
    EXPECT_EQ(options.GetOutputFile(), "");
    EXPECT_EQ(options.GetPassword(), "");
}

TEST(ProgramOptions, MissingCommandThrowsException) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "program", "--input", "input.txt",
    };
    size_t argc = std::size(argv);

    EXPECT_THROW({
        try {
            options.Parse(static_cast<int>(argc), const_cast<char**>(argv));
        } catch (const boost::program_options::required_option& e) {
            EXPECT_STREQ(e.what(), "the option 'command' is required but missing");
            throw;
        }
    }, boost::program_options::required_option);
}

TEST(ProgramOptions, InvalidCommandThrowsException) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {
        "program", "--command", "invalid_command",
        "--input", "input.txt",
    };
    size_t argc = std::size(argv);

    EXPECT_THROW(options.Parse(static_cast<int>(argc), const_cast<char**>(argv)),
                 boost::program_options::validation_error);
}

TEST(ProgramOptions, EncryptWithoutPasswordThrowsException) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "program", "--command", "encrypt",
        "--input", "input.txt",
        "--output", "output.txt",
    };
    size_t argc = std::size(argv);

    EXPECT_THROW({
        try {
            options.Parse(static_cast<int>(argc), const_cast<char**>(argv));
        } catch (const boost::program_options::required_option& e) {
            EXPECT_STREQ(e.what(), "the option 'password' is required but missing");
            throw;
        }
    }, boost::program_options::required_option);
}
