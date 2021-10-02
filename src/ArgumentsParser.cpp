#include "ArgumentsParser.hpp"

#include <string>
#include <getopt.h>
#include <iostream>

ArgumentsParser::~ArgumentsParser() {

}

bool ArgumentsParser::args_parse(int argc, char** argv) {
    int c;
    server = new std::string (argv[1]);

    while(true) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        std::string  ss;
        static struct option long_options[] = {
                {0,     required_argument,          0,                                                     0 },
                {"port",  no_argument,              0,                                                     'p' },
                {"delete",  no_argument,              0,                                                     'd' },
                {"new",  no_argument,              0,                                                     'n' },
                {0, no_argument,                    0,                                                     'T' },
                {0, no_argument,                    0,                                                     'S' },
                {0, required_argument,              0,                                                     'C' },
                {"credentials",  required_argument, 0,                                                     'c'},
                {"auth-file",    required_argument, 0,                                                     'a' },
                {"out-dir",    required_argument,   0,                                                     'o' },
                {0,         0,                      0,                                                     0 }
        };

        c = getopt_long(argc, argv, "p:dnTSC:c:a:o:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'p':
                std::cout << "Port is " << std::stoi(optarg) << std::endl;

                break;
            case 'T':
                std::cout << "Secured communication (pop3s)" << std::endl;
                ArgumentsParser::secure_pop3s = true;
                break;
            case 'S':
                std::cout << "Switch to secure (STLS)" << std::endl;
                ArgumentsParser::secure_stls = true;
                break;
            case 'c':
                std::cout << "Credentials file " << optarg << std::endl;
                ArgumentsParser::cert_file = new std::string(optarg);
                break;
            case 'C':
                std::cout << "Credentials folder " << optarg << std::endl;
                ArgumentsParser::cert_dir = new std::string(optarg);
                break;
            case 'd':
                std::cout << "Delete messages" << std::endl;
                ArgumentsParser::delete_msgs = true;
                break;
            case 'n':
                std::cout << "Only new messages" << std::endl;
                ArgumentsParser::only_new = true;
                break;
            case 'a':
                std::cout << "Auth file is " << optarg << std::endl;
                ArgumentsParser::auth_file = new std::string(optarg);
                break;
            case 'o':
                std::cout << "Output directory is " << optarg << std::endl;
                ArgumentsParser::out_dir = new std::string(optarg);
                break;
            case '?':
                std::cout << "Unknown " << c << std::endl;
                break;
            default:
                return false;
        }
    }

    if (ArgumentsParser::secure_stls && ArgumentsParser::secure_pop3s) {
        std::cerr << "Only one of (-T | -S) flags can be set" << std::endl;
        return false;
    }

    if (!ArgumentsParser::port) {
        std::cout << "Port is not set" << std::endl;
        if (ArgumentsParser::secure_pop3s) {
            ArgumentsParser::port = POP3S_PORT;
        } else {
            ArgumentsParser::port = POP3_PORT;
        }
    }

    return true;
}

std::string *ArgumentsParser::get_auth_file() {
    return this->auth_file;
}

std::string *ArgumentsParser::get_server() {
    return this->server;
}

std::string *ArgumentsParser::get_out_dir() {
    return this->out_dir;
}

short ArgumentsParser::get_port() {
    return this->port;
}

bool ArgumentsParser::is_secure() {
    if(this->secure_pop3s) {
        return true;
    }
    return false;
}
