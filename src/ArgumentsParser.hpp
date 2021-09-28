#pragma once

#include <string>
#include <getopt.h>
#include <iostream>
#include <netinet/in.h>

const short POP3S_PORT = 995;
const short POP3_PORT = 110;


class ArgumentsParser {
public:
    ~ArgumentsParser();

    bool args_parse(int argc, char** argv);

    std::string* get_server();

    short get_port();

    std::string* get_auth_file();

    std::string* get_out_dir();

    bool is_secure();

private:

    //Server name (IP address)
    std::string* server;

    //Optional port number
    unsigned short port;

    //File containing credentials for SSL/TLS 
    std::string* cert_file;

    //Directory containing credentials file
    std::string* cert_dir;

    //Delete messages flag
    bool delete_msgs = false;

    //Only new messages
    bool only_new = false;

    //Compulsory file containing autharization data
    std::string* auth_file;

    //Compulsory output directory
    std::string* out_dir;

    //Turns on encryption of all communication (pop3s)
    bool secure_pop3s = false;

    //Establishes an unencrypted connection to the server and uses the STLS command
    bool secure_stls = false;
};
