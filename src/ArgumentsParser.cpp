/* =========================================================================================================
   Case:      Brno University of Technology, ISA - Network Applications and Network Administration
   Date:      TODO
   Author:    Vladislav Sokolovskii
   Contact:   xsokol15@stud.fit.vutbr.cz
   ========================================================================================================== */

#include "ArgumentsParser.hpp"

#include <getopt.h>
#include <iostream>

ArgumentsParser::~ArgumentsParser() {
    delete server;
    delete cert_dir;
    delete cert_file;
    delete auth_file;
    delete out_dir;
}

bool ArgumentsParser::args_parse(int argc, char** argv) {
    if (argc < 3 || argc > 10) {
        USAGE;
        return false;
    } else {
        if (argv[1][0] == '-') {
            std::cerr << "Server isn't specified!" << std::endl;
            USAGE;
            return false;
        } else {
            server = new std::string(argv[1]);
        }
        for (int i = 2; i < argc; ++i) {
            switch (argv[i][1]) {
                case 'p':
                    CHECK_IF_HAS_ARG(i);
                    DEBUG_PRINT("Port is " << std::stoi(argv[i+1]));
                    ArgumentsParser::port = std::stoi(argv[++i]);
                    break;
                case 'd':
                    DEBUG_PRINT("Delete messages");
                    ArgumentsParser::delete_msgs = true;
                    break;
                case 'n':
                    DEBUG_PRINT("Only new messages");
                    ArgumentsParser::only_new = true;
                    break;
                case 'T':
                    DEBUG_PRINT("Secured communication (pop3s)");
                    ArgumentsParser::secure_pop3s = true;
                    break;
                case 'S':
                    DEBUG_PRINT("Switch to secure (STLS)");
                    ArgumentsParser::secure_stls = true;
                    break;
                case 'c':
                    CHECK_IF_HAS_ARG(i)
                    DEBUG_PRINT("Credentials file " << argv[i+1]);
                    ArgumentsParser::cert_file = new std::string(argv[++i]);
                    break;
                case 'C':
                    CHECK_IF_HAS_ARG(i);
                    DEBUG_PRINT("Credentials folder " << argv[i+1]);
                    ArgumentsParser::cert_dir = new std::string(argv[++i]);
                    break;
                case 'o':
                    CHECK_IF_HAS_ARG(i);
                    DEBUG_PRINT("Output directory is " << argv[i+1]);
                    ArgumentsParser::out_dir = new std::string(argv[++i]);
                    break;
                case 'a':
                    DEBUG_PRINT("Auth file is " << argv[i+1]);
                    ArgumentsParser::auth_file = new std::string(argv[++i]);
                    break;
                default:
                    USAGE;
                    return false;
            }
        }
    }

    if (ArgumentsParser::secure_stls && ArgumentsParser::secure_pop3s) {
        std::cerr << "Only one of (-T | -S) flags can be set" << std::endl;
        return false;
    }

    if (!ArgumentsParser::out_dir || !ArgumentsParser::auth_file) {
        USAGE;
        return false;
    }

    if (!ArgumentsParser::port) {
        DEBUG_PRINT("Port is not set");
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
    return this->secure_pop3s;
}

bool ArgumentsParser::is_stls() {
    return this->secure_stls;
}

bool ArgumentsParser::delete_flag() {
    return this->delete_msgs;
}

bool ArgumentsParser::new_flag() {
    return this->only_new;
}

std::string *ArgumentsParser::get_cert_file() {
    return this->cert_file;
}

std::string  *ArgumentsParser::get_cert_dir() {
    return this->cert_dir;
}
