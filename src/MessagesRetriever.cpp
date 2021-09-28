//
// Created by Vlad Sokolovskii on 28/09/2021.
//

#include "MessagesRetriever.hpp"

bool MessagesRetriever::set_tcp_connection(ArgumentsParser& args_parser) {
    int tcp_socket;
    this->server_addr.sin_family = AF_INET;
    this->server_addr.sin_port = htons(args_parser.get_port());

    if (!args_parser.is_secure()) {
        tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
        if(tcp_socket < 0) {
            std::cerr << "Couldn't create a socket" << std::endl;
            return false;
        }

        if (inet_aton(args_parser.get_server()->c_str(), &this->server_addr.sin_addr)) {
            std::cerr << "Invalid address" << std::endl;
            return false;
        }

        int ss = sizeof(this->server_addr);
        if (connect(tcp_socket, (struct sockaddr*)&this->server_addr, ss) < 0) {
            std::cerr << "Connection failed" << std::endl;
            return false;
        }
        std::cout << "Successful connection to the server!" << std::endl;

        char buffer[1024] = {0};

        send(tcp_socket , "USER hhh", 9, 0 );
        printf("Hello message sent\n");
        read(tcp_socket, buffer, 1024);
        printf("%s\n",buffer );
    } else {

    }
}
