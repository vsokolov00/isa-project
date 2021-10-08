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

}

bool ArgumentsParser::args_parse(int argc, char** argv) {
    int c;
    server = new std::string (argv[1]);

    while(true) {
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
                DEBUG_PRINT("Port is " << std::stoi(optarg));

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
                DEBUG_PRINT("Credentials file " << optarg);
                ArgumentsParser::cert_file = new std::string(optarg);
                break;
            case 'C':
                DEBUG_PRINT("Credentials folder " << optarg);
                ArgumentsParser::cert_dir = new std::string(optarg);
                break;
            case 'd':
                DEBUG_PRINT("Delete messages");
                ArgumentsParser::delete_msgs = true;
                break;
            case 'n':
                DEBUG_PRINT("Only new messages");
                ArgumentsParser::only_new = true;
                break;
            case 'a':
                DEBUG_PRINT("Auth file is " << optarg);
                ArgumentsParser::auth_file = new std::string(optarg);
                break;
            case 'o':
                DEBUG_PRINT("Output directory is " << optarg);
                ArgumentsParser::out_dir = new std::string(optarg);
                break;
            case '?':
                std::cerr << "Unknown " << c << std::endl;
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

bool ArgumentsParser::delete_flag() {
    return this->delete_msgs;
}

bool ArgumentsParser::new_flag() {
    return this->only_new;
}
