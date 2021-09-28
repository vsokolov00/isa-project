#include "popcl.hpp"
#include "ArgumentsParser.hpp"

#include <iostream>

int main(int argc, char** argv) {
    std::cout << "Application start." << std::endl;

    ArgumentsParser args_parser;


    if(!args_parser.args_parse(argc, argv)) {
        return EXIT_FAILURE;
    }


    return 0;
}