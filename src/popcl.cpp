/* =========================================================================================================
   Case:      Brno University of Technology, ISA - Network Applications and Network Administration
   Date:      07.11.2021
   Author:    Vladislav Sokolovskii
   Contact:   xsokol15@stud.fit.vutbr.cz
   Description: POP3 client with the TLS support
   ========================================================================================================== */

#include <iostream>

#include "ArgumentsParser.hpp"
#include "MessagesReceiver.hpp"


int main(int argc, char** argv) {
    //to enable debug helping messages see CMakeLists.txt file
    DEBUG_PRINT("Application starts.");

    ArgumentsParser args_parser{};

    if(!args_parser.args_parse(argc, argv)) {
        return EXIT_FAILURE;
    }

    MessagesReceiver msg_retriever{};

    if(!msg_retriever.set_tcp_connection(args_parser)) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
