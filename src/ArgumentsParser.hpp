#ifndef ARGPARSER_HPP
#define ARGPARSER_HPP

#include <string>

class ArgumentsParser {
public:
    ~ArgumentsParser();

    bool args_parse(int argc, char** argv);

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
    bool delete_msgs;

    //Compulsory file containing autharization data
    std::string* auth_file;

    //Compulsory output directory
    std::string* out_dir;
};

#endif
