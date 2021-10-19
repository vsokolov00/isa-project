/* =========================================================================================================
   Case:      Brno University of Technology, ISA - Network Applications and Network Administration
   Date:      TODO
   Author:    Vladislav Sokolovskii
   Contact:   xsokol15@stud.fit.vutbr.cz
   ========================================================================================================== */

#include "MessagesReceiver.hpp"

#include <iostream>
#include <chrono>
#include <unistd.h>
#include <regex>
#include <fstream>
#include <sstream>

#include <sys/socket.h>
#include <arpa/inet.h>


MessagesReceiver::MessagesReceiver() {
    this->_server_addr = new sockaddr_in;
}

MessagesReceiver::~MessagesReceiver() {
    delete this->_server_addr;
    close(this->_tcp_socket);
    if (bio) BIO_reset(bio);
    if (_ctx) SSL_CTX_free(_ctx);
}

bool MessagesReceiver::set_tcp_connection(ArgumentsParser& args_parser) {
    std::string host_port = *args_parser.get_server() + ":" + std::to_string(args_parser.get_port());

    if (args_parser.is_secure()) {
        init_context(args_parser);
        bio = BIO_new_ssl_connect(this->_ctx);
    } else {
        bio = BIO_new_connect(host_port.c_str());
    }

    if (!bio) {
        std::cerr << "The creation of a new BIO object failed." << std::endl;
        return false;
    }

    if (args_parser.is_secure()) {
        BIO_get_ssl(bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
        BIO_set_conn_hostname(bio, host_port.c_str());
    }

    if (BIO_do_connect(bio) <= 0) {
        std::cerr << "Connection to the server " << args_parser.get_server()->c_str() << " failed." << std::endl;
        return false;
    }
    this->_is_connected = true;

    if (args_parser.is_secure()) {
        if (ssl && SSL_get_verify_result(ssl) != X509_V_OK) {
            std::cerr << "Verification of certificates failed." << std::endl;
            return false;
        }
    }

    if (!check_response_state(get_response(bio, false))) {
        std::cerr << "Connection to the server " << args_parser.get_server()->c_str() << " failed." << std::endl;
        return false;
    }

    if (args_parser.is_stls()) {
        std::string stls_req = "STLS\n";
        if (BIO_write(bio, stls_req.c_str(), stls_req.size()) <= 0) {
            return false;
        }
        if (!check_response_state(get_response(bio, false))) {
            std::cerr << "WARNING: STLS command failed or isn't supported by the server.\nWARNING: A plain-text transmission will be established instead." << std::endl;
        } else {
            init_context(args_parser);

            if (!(ssl = SSL_new(_ctx))) {
                std::cerr << "The creation of a new SSL structure failed." << std::endl;
                return false;
            }
            SSL_set_bio(ssl, bio, bio);
            int ret = SSL_connect(ssl);
            if (ret <= 0) {
                std::cerr << "The TLS/SSL handshake was not successful" << std::endl;
                return false;
            }
            if (ssl && SSL_get_verify_result(ssl) != X509_V_OK) {
                std::cerr << "Verification of certificates failed." << std::endl;
                return false;
            } else {
                _is_tls_established = true;
            }
        }
    }

    //LOG IN TO THE MAIL
    auto credentials = parse_auth_file(args_parser);
    if (!authorize(bio, std::get<0>(credentials), std::get<1>(credentials))) {
        return false;
    }

    int num = get_number_of_emails(bio);
    if (num > 0) {
        auto e_mail = save_emails(bio, num, *args_parser.get_out_dir(), args_parser);
        std::cout << e_mail << ((e_mail == 1) ? " e-mail was " : " e-mails were ") << "downloaded" << std::endl;
    } else {
        std::cout << "Inbox is empty" << std::endl;
    }

    return true;
}

void MessagesReceiver::init_context(ArgumentsParser& args_parser) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if (this->_ctx = SSL_CTX_new(SSLv23_client_method()), !this->_ctx) {
        std::cerr << "The creation of a new SSL_CTX object failed." << std::endl;
    }

    int verify = set_certificate_location(args_parser);
    if (!verify) {
        std::cerr << "Verify contains bad value" << std::endl;//TODO
    }
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
            if (_is_tls_established)
                read_data = SSL_read(ssl, response_buffer, MAX_PACKET_SIZE - 1);
            else
                read_data = BIO_read(bio, response_buffer, MAX_PACKET_SIZE - 1);

            if (read_data >= 0) {
                if (read_data > 0) {
                    response_buffer[read_data] = '\0';
                    response += response_buffer;
                    auto out = split(response, '\n');

                    //indicates the end of the response message
                    if (out.back() == ".\r") {
                        return response;
                    }

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
            break;
        }
    } while (read_data);

    return response;
}

std::tuple<std::string, std::string> MessagesReceiver::parse_auth_file(ArgumentsParser& args_parser) {
    std::string username, password;

    std::string auth_file = *args_parser.get_auth_file();
    std::ifstream infile(auth_file);

    if (!infile.is_open()) {
        std::cerr << "Could not open the file - '"<< auth_file << "'" << std::endl;
        return {"_bad", "_bad"};
    }
    std::string line;

    std::getline(infile, line);
    std::vector<std::string> splitted = split(line, '=');
    if (splitted.size() >= 2 && trim(splitted[0]) == "username") {
        username = trim(splitted[1]);
    } else {
        std::cerr << "Could not log in to the server " << *args_parser.get_server() << std::endl;
        return {"_bad", "_bad"};
    }

    std::getline(infile, line);
    splitted = split(line, '=');
    if (trim(splitted[0]) == "password") {
        password = trim(splitted[1]);
    } else {
        std::cerr << "Bad auth file format" << std::endl;
    }

    return {username, password};
}

bool MessagesReceiver::check_response_state(const std::string& response) {
    return response.substr(0,3) == "+OK";
}

bool MessagesReceiver::authorize(BIO* bio, std::string username, std::string password) {
    if (username == "_bad" && password == "_bad") {
        return false;
    }
    std::string user_req = "USER " + username + "\n";
    std::string pswd_req = "PASS " + password + "\n";

    SEND_REQUEST(user_req);


    if (!check_response_state(get_response(bio, false))) {
        std::cerr << "Couldn't log in to the server." << std::endl;
        return false;
    }

    SEND_REQUEST(pswd_req);
    if (!check_response_state(get_response(bio, false))) {
        std::cerr << "Couldn't log in to the server." << std::endl;
        return false;
    }

    return true;
}

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
    std::string req = "STAT\n";
    SEND_REQUEST(req);
    auto out = split(get_response(bio, false), ' ');

    return std::stoi(out[1]);
}

//check if out_dir ends with /
int MessagesReceiver::save_emails(BIO *bio, int total, const std::string& output_dir, ArgumentsParser& args_parser) {
    int successfully_saved = 0;
    std::fstream old_emails_db;

    old_emails_db.open(OLDMAILS, std::ios_base::app);

    for (int i = 1; i <= total; i++) {
        std::string file_name = "mail-";
        std::string req = "RETR ";
        req += std::to_string(i) + "\n";

        SEND_REQUEST(req);

        file_name += std::to_string(i);

        std::string out = get_response(bio, true);

        if (args_parser.new_flag() && is_email_old(out)) {
            continue;
        }

        std::string response = out.substr(0, out.find('\n'));
        if (!check_response_state(response)) {
            continue;
        }
        auto from = out.find('\n') + 1;
        out = out.substr(from, out.size() - from - FINAL_PERIOD);

        std::fstream outfile;
        outfile.open(output_dir + "/" + file_name , std::ios_base::out);

        if (!outfile.is_open()) {
            std::cerr << "Failed to open " << file_name << '\n';
        } else {
            outfile << out;
            DEBUG_PRINT("Done writing " << file_name);
            successfully_saved++;

            std::string msg_id = check_email(out);
            if (!msg_id.empty()) { old_emails_db << msg_id << std::endl; }

            if(args_parser.delete_flag()) {
                if(delete_email(bio, i)) { DEBUG_PRINT(file_name << " was deleted"); }
            }
        }
        outfile.close();
    }
    if (old_emails_db.is_open()) {
        old_emails_db.close();
    }

    std::string req = "QUIT\n";

    SEND_REQUEST(req);

    if(get_response(bio, false) == "DONE\r\n") {
        DEBUG_PRINT("State updated");
    }

    return successfully_saved;
}

bool MessagesReceiver::delete_email(BIO *bio, int msg_number) {
    if(this->_is_connected) {
        std::string req = "DELE ";
        req += std::to_string(msg_number) + "\n";

        SEND_REQUEST(req)

        if (!check_response_state(get_response(bio, false))) {
            std::cerr << "Couldn't delete a message" << std::endl;
            return false;
        }
        return true;
    } else {
        std::cerr << "Connection failed" << std::endl;
    }
    return false;

}

std::string MessagesReceiver::trim(const std::string &s)
{
    auto start = s.begin();
    while (start != s.end() && std::isspace(*start)) {
        start++;
    }
 
    auto end = s.end();
    do {
        end--;
    } while (std::distance(start, end) > 0 && std::isspace(*end));
 
    return std::string(start, end + 1);
}

std::string MessagesReceiver::get_message_id(const std::string out) {
    std::regex pattern(".*Message-ID:\\s<.*>.*", std::regex_constants::icase);
    std::smatch match;

    if (std::regex_search(out.begin(), out.end(), match, pattern))
        return split(match[0], ' ')[1];
    return nullptr;
}

bool MessagesReceiver::is_email_old(const std::string e_mail) {
    std::ifstream input(OLDMAILS);
    for (std::string line; getline(input, line);) {
        if (get_message_id(e_mail) == line) {
            return true;
        }
    }
    return false;
}

std::string MessagesReceiver::check_email(std::string out) {
    bool is_new = true;
    std::string msg_id = get_message_id(out);
    std::ifstream input(OLDMAILS);
    for (std::string line; getline(input, line);) {
        if (msg_id == line) {
            is_new = false;
            break;
        }
    }
    if (is_new) {
        return msg_id;
    } else {
        return "";
    }
}

int MessagesReceiver::set_certificate_location(ArgumentsParser& args_parser) {
    int verify;

    if (args_parser.get_cert_dir() && args_parser.get_cert_file()) {
        verify = SSL_CTX_load_verify_locations(this->_ctx, args_parser.get_cert_file()->c_str(), args_parser.get_cert_dir()->c_str());
    } else if (args_parser.get_cert_dir()) {
        verify = SSL_CTX_load_verify_locations(this->_ctx, nullptr, args_parser.get_cert_dir()->c_str());
    } else if (args_parser.get_cert_file()) {
        verify = SSL_CTX_load_verify_locations(this->_ctx, args_parser.get_cert_file()->c_str(), nullptr);
    } else {
        verify = SSL_CTX_set_default_verify_paths(this->_ctx);
    }

    return verify;
}
