#include <fstream>
#include <iostream>
#include <print>

#include "cmd_options.h"
#include "crypto_guard_ctx.h"

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            {
                std::ifstream inStream(options.GetInputFile(), std::ios::binary);
                std::ofstream outStream(options.GetOutputFile(), std::ios::binary);

                cryptoCtx.EncryptFile(inStream, outStream, options.GetPassword());

                std::print("File encoded successfully\n");
            }
            break;

        case COMMAND_TYPE::DECRYPT:
            {
                std::ifstream inStream(options.GetInputFile(), std::ios::binary);
                std::ofstream outStream(options.GetOutputFile(), std::ios::binary);

                cryptoCtx.DecryptFile(inStream, outStream, options.GetPassword());

                std::print("File decoded successfully\n");
            }
            break;

        case COMMAND_TYPE::CHECKSUM:
            {
                std::ifstream inStream(options.GetInputFile(), std::ios::binary);

                auto checksum = cryptoCtx.CalculateChecksum(inStream);

                std::print("Checksum: {}\n", checksum);
            }
            break;

        default:
            throw std::runtime_error("Unsupported command");
        }

    } catch (const CryptoGuard::ProgramOptionHelpRequested &e) {
        return 1;
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
