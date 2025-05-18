#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <iostream>
#include <fstream>
#include <stdexcept>

int main(int argc, char* argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        if (!options.Parse(argc, argv)) {
            return 0;
        }

        const auto inPath  = options.GetInputFile();
        std::ifstream inFile(inPath, std::ios::binary);
        if (!inFile.is_open()) {
            std::cerr << "Error: cannot open input file: " << inPath << "\n";
            return 1;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using CMD = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
            case CMD::ENCRYPT: {
                const auto outPath = options.GetOutputFile();
                std::ofstream outFile(outPath, std::ios::binary);
                if (!outFile.is_open()) {
                    std::cerr << "Error: cannot open output file: " << outPath << "\n";
                    return 1;
                }

                const auto pwd = options.GetPassword();
                cryptoCtx.EncryptFile(inFile, outFile, pwd);
                std::cout << "File encrypted successfully: " << outPath << "\n";
                break;
            }

            case CMD::DECRYPT: {
                const auto outPath = options.GetOutputFile();
                std::ofstream outFile(outPath, std::ios::binary);
                if (!outFile.is_open()) {
                    std::cerr << "Error: cannot open output file: " << outPath << "\n";
                    return 1;
                }

                const auto pwd = options.GetPassword();
                cryptoCtx.DecryptFile(inFile, outFile, pwd);
                std::cout << "File decrypted successfully: " << outPath << "\n";
                break;
            }

            case CMD::CHECKSUM: {
                std::string sum = cryptoCtx.CalculateChecksum(inFile);
                std::cout << "Checksum: " << sum << "\n";
                break;
            }

            default:
                throw std::runtime_error("Unsupported command");
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}