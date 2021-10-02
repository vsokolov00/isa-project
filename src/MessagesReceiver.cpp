//
// Created by Vlad Sokolovskii on 28/09/2021.
//

#include "MessagesReceiver.hpp"

#include <chrono>
#include <unistd.h>
#include <regex>
#include <fstream>
#include <sstream>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <iostream>


MessagesReceiver::MessagesReceiver() {
    this->_server_addr = new sockaddr_in;
}

MessagesReceiver::~MessagesReceiver() {
    delete this->_server_addr;
    close(this->_tcp_socket);
    SSL_CTX_free(this->_ctx);
}


bool MessagesReceiver::set_tcp_connection(ArgumentsParser& args_parser) {

    //insecure connection via port 110
    if (!args_parser.is_secure()) {
        if (open_connection(args_parser) == UNSUCCESS) {
            return false;
        }
        //secure TLS connection via port 995
    } else {
        init_context();

        SSL *ssl = nullptr;
        BIO *bio = BIO_new_ssl_connect(this->_ctx);

        if (!bio) {
            std::cerr << "Connection failed." << std::endl;
            return false;
        }
        std::string host_port = *args_parser.get_server() + ":" + std::to_string(args_parser.get_port());

        BIO_get_ssl(bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
        BIO_set_conn_hostname(bio, host_port.c_str());

        if (BIO_do_connect(bio) <= 0) {
            std::cerr << "Connection to the server " << args_parser.get_server()->c_str() << "failed." << std::endl;
            return false;
        }
        if (ssl && SSL_get_verify_result(ssl) != X509_V_OK) {
            std::cerr << "Verification of certificates failed." << std::endl;
            return false;
        }

        if (!check_response_state(get_response(bio, false))) {
            return false;
        }
        auto credentials = parse_auth_file(args_parser.get_auth_file());
        if (!authorize(bio, std::get<0>(credentials), std::get<1>(credentials))) {
            return false;
        }
        std::cout << get_response(bio, false);
        int num = get_number_of_emails(bio);
        if (num > 0) {
            auto e_mail = save_emails(bio, num, *args_parser.get_out_dir());
            std::cout << "Staženo " << e_mail << " zpráv." << std::endl;
        }

    }

    return true;
}

void MessagesReceiver::init_context() {
    const SSL_METHOD *method;
    int verify;

    SSL_library_init();
    OpenSSL_add_all_algorithms();       /* Load cryptos, et.al. */
    SSL_load_error_strings();           /* Bring in and register error messages */

    this->_ctx = SSL_CTX_new(SSLv23_client_method());          /* Create new context */

    verify = SSL_CTX_set_default_verify_paths(this->_ctx);

    if (!verify) {
        std::cerr << "Verification of certificates failed." << std::endl;
        return;
    }
}

int MessagesReceiver::open_connection(ArgumentsParser& args_parser) {
    this->_tcp_socket = socket(AF_INET, SOCK_STREAM, 0);

    if(this->_tcp_socket < 0) {
        std::cerr << "Couldn't create a socket" << std::endl;
        return UNSUCCESS;
    }
    if (!inet_aton(args_parser.get_server()->c_str(), &this->_server_addr->sin_addr)) {
        std::cerr << "Invalid address" << std::endl;
        return UNSUCCESS;
    }
    this->_server_addr->sin_family = AF_INET;
    this->_server_addr->sin_port = htons(args_parser.get_port());

    if (connect(this->_tcp_socket, (struct sockaddr*)this->_server_addr, sizeof(*this->_server_addr))) {
        std::cerr << "Connection failed" << std::endl;
        return UNSUCCESS;
    }
    std::cout << "Successful connection to the server!" << std::endl;
    this->_is_connected = true;

    return 0;
}

std::string MessagesReceiver::get_response(BIO* bio, bool period_indicator) {
    int read_data = 0;
    char response_buffer[MAX_PACKET_SIZE] = {'\0'};
    std::string response;

    do {
        bool first_read = true;
        bool read_done = false;
        while (BIO_should_retry(bio) || first_read) {
            first_read = false;
            read_data = BIO_read(bio, response_buffer, MAX_PACKET_SIZE - 1);
            if (read_data >= 0) {
                if (read_data > 0) {
                    response_buffer[read_data] = '\0';
                    response += response_buffer;
                    auto out = split(response, '\n');
                    if (out.back() == ".\r") {
                        return response;
                    }
                    //std::cout << response;
                    if (!period_indicator) {
                        return response;
                    }
                }
                read_done = true;
                break;
            }
        }
        if (!read_done) {
            std::cerr << "Bio read error" << std::endl;
        }
    } while (read_data);

    return response;
}

std::tuple<std::string, std::string> MessagesReceiver::parse_auth_file(std::string* path_to_auth_file) {
    std::ifstream infile(path_to_auth_file->c_str());
    std::string line;
    while (std::getline(infile, line))
    {
        std::cout << line;
    }

    return std::tuple<std::string, std::string>("isa.test@gmx.com", "04072010o1q2w3e");
}

bool MessagesReceiver::check_response_state(const std::string& response) {
    return response.substr(0,3) == "+OK";
}

bool MessagesReceiver::authorize(BIO* bio, std::string username, std::string password) {
    std::string user_req = "USER " + username + "\n";
    std::string pswd_req = "PASS " + password + "\n";

    if (BIO_write(bio, user_req.c_str(), user_req.size()) <= 0) {
        return false;
    }
    if (!check_response_state(get_response(bio, false))) {
        return false;
    }
    if (BIO_write(bio, pswd_req.c_str(), pswd_req.size()) <= 0) {
        return false;
    }

    return true;
}

//https://www.fluentcpp.com/2017/04/21/how-to-split-a-string-in-c/
std::vector<std::string> MessagesReceiver::split(const std::string& s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter))
    {
        tokens.push_back(token);
    }
    return tokens;
}

int MessagesReceiver::get_number_of_emails(BIO *bio) {
    const char* str = "STAT\n";
    BIO_write(bio, str, strlen(str));
    auto out = split(get_response(bio, false), ' ');
    return std::stoi(out[1]);
}

//check if out_dir ends with /
int MessagesReceiver::save_emails(BIO *bio, int total, const std::string& output_dir) {
    int successfully_saved = 0;
    std::string req = "RETR ";
    for (int i = 1; i <= total; i++) {
        std::string file_name = "mail-";
        req += std::to_string(i) + "\n";
        BIO_write(bio, req.c_str(), req.size());
        file_name += std::to_string(i);

        auto out = get_response(bio, true);
        std::fstream outfile;
        //outfile.open("../" + output_dir + "/" + file_name , std::ios_base::out);
        outfile.open("./" + output_dir + "/" + file_name , std::ios_base::out);

        if (!outfile.is_open()) {
            std::cerr << "Failed to open " << file_name << '\n';
        } else {
            outfile << out;
            std::cerr << "Done Writing!" << std::endl;
            successfully_saved++;
        }
        outfile.close();
    }
    return successfully_saved;
}

