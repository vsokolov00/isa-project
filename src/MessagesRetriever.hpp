//
// Created by Vlad Sokolovskii on 28/09/2021.
//

#ifndef POPCL_MESSAGESRETRIEVER_H
#define POPCL_MESSAGESRETRIEVER_H

#include "ArgumentsParser.hpp"

#include <chrono>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

class MessagesRetriever {
public:
    //Establish TCP connection with the server
    bool set_tcp_connection(ArgumentsParser&);

private:
    struct sockaddr_in server_addr;
};


#endif //POPCL_MESSAGESRETRIEVER_H
