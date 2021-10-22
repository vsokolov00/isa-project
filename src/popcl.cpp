
/* =========================================================================================================
   Case:      Brno University of Technology, ISA - Network Applications and Network Administration
   Date:      TODO
   Author:    Vladislav Sokolovskii
   Contact:   xsokol15@stud.fit.vutbr.cz
   Description: POP3 client with the TLS support
   ========================================================================================================== */

#include <iostream>
#include <chrono>

#include "ArgumentsParser.hpp"
#include "MessagesReceiver.hpp"


int main(int argc, char** argv) {
    //to enable debug helping messages see CMakeLists.txt file
    DEBUG_PRINT("Application starts.");
    using std::chrono::milliseconds;

    ArgumentsParser args_parser{};

    if(!args_parser.args_parse(argc, argv)) {
        return EXIT_FAILURE;
    }

    MessagesReceiver msg_retriever{};

    auto t1 = std::chrono::high_resolution_clock::now();
    if(!msg_retriever.set_tcp_connection(args_parser)) {
        return EXIT_FAILURE;
    }
    auto t2 = std::chrono::high_resolution_clock::now();

    auto ms_int = std::chrono::duration_cast<milliseconds>(t2 - t1);
    std::cout << ms_int.count()/1000 << "s\n";


    return EXIT_SUCCESS;
}
