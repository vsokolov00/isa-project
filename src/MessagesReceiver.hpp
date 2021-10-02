//
// Created by Vlad Sokolovskii on 28/09/2021.
//

#pragma once

#include <atomic>
#include <thread>
#include <queue>
#include <openssl/ssl.h>

#include "ArgumentsParser.hpp"

#define MAX_PACKET_SIZE 4096

#define UNSUCCESS -1

class MessagesReceiver {
public:
    MessagesReceiver();

    ~MessagesReceiver();

    //Establish TCP connection with the server
    bool set_tcp_connection(ArgumentsParser&);

private:
    int _tcp_socket;
    SSL_CTX* _ctx;

    struct sockaddr_in* _server_addr;

    std::atomic<bool> _is_connected;
    std::atomic<bool> _is_closed;
    std::thread* _packets_receiver = nullptr;
    std::mutex _subscribers_mtx;

    void receive_packets();
    std::string get_response(BIO* bio, bool period_indicator);
    void init_context();
    int open_connection(ArgumentsParser& args_parser);

    std::tuple<std::string, std::string> parse_auth_file(std::string* path_to_auth_file);
    static bool check_response_state(const std::string& response);
    bool authorize(BIO* bio, std::string username, std::string password);
    int get_number_of_emails(BIO* bio);
    int save_emails(BIO* bio, int total, const std::string& out_dir);

    std::vector<std::string> split(const std::string& s, char delimiter);
};

