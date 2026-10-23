#include "cmd_options.h"

#include <format>
#include <iostream>
#include <stdexcept>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // clang-format off
    desc_.add_options()
        ("help,h", "Show help message")
        ("command,c", po::value<std::string>(), "Command: encrypt, decrypt or checksum")
        ("input,i", po::value<std::string>(&inputFile_), "Path to the input file")
        ("output,o", po::value<std::string>(&outputFile_), "Path to the output file")
        ("password,p", po::value<std::string>(&password_), "Password for encryption/decryption");
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.contains("help")) {
        helpRequested_ = true;
        std::cout << desc_ << '\n';
        return;
    }

    po::notify(vm);

    if (!vm.contains("command")) {
        throw std::runtime_error{"Missing required option: command"};
    }

    const auto commandName = vm["command"].as<std::string>();
    const auto it = commandMapping_.find(commandName);
    if (it == commandMapping_.end()) {
        throw std::runtime_error{
            std::format("Unknown command: '{}'. Supported commands: encrypt, decrypt, checksum", commandName)};
    }
    command_ = it->second;

    auto requireOption = [&vm](std::string_view name) {
        if (!vm.contains(std::string{name})) {
            throw std::runtime_error{std::format("Missing required option: {}", name)};
        }
    };

    requireOption("input");
    if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        requireOption("output");
        requireOption("password");
    }
}

}  // namespace CryptoGuard
