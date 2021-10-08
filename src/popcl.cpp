/* =========================================================================================================
   Case:      Brno University of Technology, ISA - Network Applications and Network Administration
   Date:      TODO
   Author:    Vladislav Sokolovskii
   Contact:   xsokol15@stud.fit.vutbr.cz
   Description: POP3 client with the TLS support
   ========================================================================================================== */

#include <iostream>

#include "ArgumentsParser.hpp"
#include "MessagesReceiver.hpp"


int main(int argc, char** argv) {
    DEBUG_PRINT("Application starts.");

    ArgumentsParser args_parser{};
    MessagesReceiver msg_retriever{};

    if(!args_parser.args_parse(argc, argv)) {
        return EXIT_FAILURE;
    }
    if(!msg_retriever.set_tcp_connection(args_parser)) {
        return EXIT_FAILURE;
    }

    return 0;
}
