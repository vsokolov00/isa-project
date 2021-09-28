//
// Created by Vlad Sokolovskii on 28/09/2021.
//

#include "MessagesReceiver.hpp"

MessagesReceiver::MessagesReceiver() {
    this->_server_addr = new sockaddr_in;
}

MessagesReceiver::~MessagesReceiver() {
    delete this->_server_addr;
}


bool MessagesReceiver::set_tcp_connection(ArgumentsParser& args_parser) {
    if (!args_parser.is_secure()) {
        this->_tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
        if(this->_tcp_socket < 0) {
            std::cerr << "Couldn't create a socket" << std::endl;
            return false;
        }

        if (!inet_aton(args_parser.get_server()->c_str(), &this->_server_addr->sin_addr)) {
            std::cerr << "Invalid address" << std::endl;
            return false;
        }
        this->_server_addr->sin_family = AF_INET;
        this->_server_addr->sin_port = htons(args_parser.get_port());

        if (connect(this->_tcp_socket, (struct sockaddr*)this->_server_addr, sizeof(*this->_server_addr))) {
            std::cerr << "Connection failed" << std::endl;
            return false;
        }
        std::cout << "Successful connection to the server!" << std::endl;
        this->_is_connected = true;

    } else {
        //secure connection
    }

    //this->_packets_receiver = new std::thread(&MessagesReceiver::receive_packets, this);
    this->receive_packets();
}

void MessagesReceiver::receive_packets() {
    while(this->_is_connected) {
        char buffer[MAX_PACKET_SIZE];

        auto bytes_received = recv(this->_tcp_socket, buffer, MAX_PACKET_SIZE, 0);
        if(bytes_received < 1) {
            if(bytes_received == 0) {
                std::cerr << "Connection to the server is closed" << std::endl;
            } else {
                std::cerr << "ERROR" << std::endl;
            }
            this->_is_connected = false;
            return;
        }
        std::cout << buffer << std::endl;
    }
}

