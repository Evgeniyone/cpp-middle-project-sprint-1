#include "cmd_options.h"
#include <boost/program_options.hpp>
#include <cctype>
#include <iostream>
#include <ostream>
#include <ranges>
#include <stdexcept>
#include <string>

namespace CryptoGuard {
namespace po = boost::program_options;
ProgramOptions::ProgramOptions() : desc_("Allowed options") {
  // clang-format off
  desc_.add_options()
  ("help,h", "Help screen")
  ("command,c", po::value<std::string>()->required(), "Command to execute encrypt,decrypt,checksum")
  ("input,i", po::value<std::string>(&inputFile_)->required(), "Input file")
  ("output,o", po::value<std::string>(&outputFile_), "Output file")
  ("password,p", po::value<std::string>(&password_), "Password for encode/decode");
  // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {

  po::variables_map vm;

  store(parse_command_line(argc, argv, desc_), vm);

  if (vm.contains("help")) {
    std::cout << desc_ << "\n";
    return false;
  }

  notify(vm);

  std::string cmd = vm["command"].as<std::string>();
  cmd = cmd |
        std::views::transform([](unsigned char c) { return std::tolower(c); }) |
        std::ranges::to<std::string>();

  auto it = commandMapping_.find(cmd);
  if (it == commandMapping_.end()) {
    throw po::validation_error(po::validation_error::invalid_option_value,
                               "command,c");
  }

  command_ = it->second;

  if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
    if (!vm.contains("output")) {
      throw std::runtime_error("--output,o required for encrypt,decrypt");
    }
    if (!vm.contains("password")) {
      throw std::runtime_error("--password,p required for encrypt, decrypt");
    }
  }

  return true;
}

} // namespace CryptoGuard
