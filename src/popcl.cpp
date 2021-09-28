#include "popcl.hpp"

#include <iostream>

int main(int argc, char** argv) {
    std::cout << "Application starts." << std::endl;

    ArgumentsParser args_parser{};
    MessagesReceiver msg_retriever{};

    if(!args_parser.args_parse(argc, argv)) {
        return EXIT_FAILURE;
    }
    if(!msg_retriever.set_tcp_connection(args_parser)) {
        return EXIT_FAILURE;
    }

    std::cout << "Successfully finished" << std::endl;
    return 0;
}