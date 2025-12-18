#include <iostream>
#include <string>

#include <boost/program_options.hpp>
#include <boost/program_options/errors.hpp>

#include "cmd_options.h"

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;

    desc_.add_options()
        ("help", "produce help message")
        ("command", po::value<std::string>(), "command (encrypt, decrypt, checksum)")
        ("input,i", po::value<std::string>(), "input file")
        ("output,o", po::value<std::string>(), "output file")
        ("password,p", po::value<std::string>(), "password")
    ;
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    namespace po = boost::program_options;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << "\n";
        throw ProgramOptionHelpRequested();
    }

    if (!vm.count("command"))
        throw po::required_option("command");
    auto command_str = vm["command"].as<std::string>();
    if (auto it = commandMapping_.find(command_str); it == commandMapping_.end()) {
        throw po::validation_error(po::validation_error::invalid_option_value, "command", command_str);
    } else {
        command_ = it->second;
    }

    if (!vm.count("input"))
        throw po::required_option("input");
    inputFile_ = vm["input"].as<std::string>();

    switch (command_) {
    case ProgramOptions::COMMAND_TYPE::ENCRYPT:
        if (!vm.count("output"))
            throw po::required_option("output");
        outputFile_ = vm["output"].as<std::string>();

        if (!vm.count("password"))
            throw po::required_option("password");
        password_ = vm["password"].as<std::string>();
        break;

    case ProgramOptions::COMMAND_TYPE::DECRYPT:
        if (!vm.count("output"))
            throw po::required_option("output");
        outputFile_ = vm["output"].as<std::string>();

        if (!vm.count("password"))
            throw po::required_option("password");
        password_ = vm["password"].as<std::string>();
        break;

    case ProgramOptions::COMMAND_TYPE::CHECKSUM:
        break;
    }
}

}  // namespace CryptoGuard
