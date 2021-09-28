//
// Created by Vlad Sokolovskii on 28/09/2021.
//

#ifndef POPCL_MESSAGESRETRIEVER_H
#define POPCL_MESSAGESRETRIEVER_H

#include "ArgumentsParser.hpp"

#include <chrono>
#include <thread>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 4096

class MessagesReceiver {
public:
    MessagesReceiver();

    ~MessagesReceiver();

    //Establish TCP connection with the server
    bool set_tcp_connection(ArgumentsParser&);

private:
    int _tcp_socket;

    struct sockaddr_in* _server_addr;

    std::atomic<bool> _is_connected;
    std::atomic<bool> _is_closed;
    std::thread* _packets_receiver = nullptr;
    std::mutex _subscribers_mtx;


    void receive_packets();
};


#endif //POPCL_MESSAGESRETRIEVER_H
