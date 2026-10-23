#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <format>
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        if (options.IsHelpRequested()) {
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        auto openFile = [](const std::string &path, std::ios::openmode mode) {
            std::fstream file{path, mode | std::ios::binary};
            if (!file.is_open()) {
                throw std::runtime_error{std::format("Failed to open file: '{}'", path)};
            }
            return file;
        };

        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            auto inStream = openFile(options.GetInputFile(), std::ios::in);
            auto outStream = openFile(options.GetOutputFile(), std::ios::out | std::ios::trunc);
            cryptoCtx.EncryptFile(inStream, outStream, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            auto inStream = openFile(options.GetInputFile(), std::ios::in);
            auto outStream = openFile(options.GetOutputFile(), std::ios::out | std::ios::trunc);
            cryptoCtx.DecryptFile(inStream, outStream, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            auto inStream = openFile(options.GetInputFile(), std::ios::in);
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inStream));
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}