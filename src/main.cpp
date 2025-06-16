#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <print>

using namespace CryptoGuard;

std::fstream GetFilestream(std::string_view filename, std::ios::openmode mode) {
    std::fstream file(std::string(filename), mode);
    if (!file.is_open()) {
        throw std::runtime_error(std::format("Cannot open file: {}", filename));
    }
    return file;
}

int main(int argc, char* argv[]) {
    try {
        ProgramOptions options;
        if (!options.Parse(argc, argv)) {
            return 0;  // help or usage printed
        }

        auto inFile = GetFilestream(options.GetInputFile(), std::ios::in | std::ios::binary);

        CryptoGuardCtx cryptoCtx;
        using CMD = ProgramOptions::COMMAND_TYPE;

        switch (options.GetCommand()) {
            case CMD::ENCRYPT: {
                auto outFile = GetFilestream(options.GetOutputFile(), std::ios::out | std::ios::binary);
                cryptoCtx.EncryptFile(inFile, outFile, options.GetPassword());
                std::println("File encrypted successfully: {}", options.GetOutputFile());
                break;
            }

            case CMD::DECRYPT: {
                auto outFile = GetFilestream(options.GetOutputFile(), std::ios::out | std::ios::binary);
                cryptoCtx.DecryptFile(inFile, outFile, options.GetPassword());
                std::println("File decrypted successfully: {}", options.GetOutputFile());
                break;
            }

            case CMD::CHECKSUM: {
                std::string sum = cryptoCtx.CalculateChecksum(inFile);
                std::println("Checksum: {}", sum);
                break;
            }

            default:
                throw std::runtime_error("Unsupported command");
        }

    } catch (const std::exception& e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}