/* =========================================================================================================
   Case:      Brno University of Technology, ISA - Network Applications and Network Administration
   Date:      TODO
   Author:    Vladislav Sokolovskii
   Contact:   xsokol15@stud.fit.vutbr.cz
   Description: This class is responsible for the correct command line arguments parsing and storing the
                information about the set flags and given arguments
   ========================================================================================================== */

#pragma once

#include <string>

#ifdef DEBUG
#define DEBUG_TEST 1
#else
#define DEBUG_TEST 0
#endif

#define DEBUG_PRINT(str) \
            do { if (DEBUG_TEST) std::cerr << str  << std::endl;} while (0)

const short POP3S_PORT = 995;
const short POP3_PORT = 110;


class ArgumentsParser {
public:
    ~ArgumentsParser();

    /**
     * This function parses the arguments and stores their values to the private variables
     * @param argc Numer of the arguments
     * @param argv Array of the arguments
     * @return Returns true if the arguments were parsed successfully, otherwise returns false
     */
    bool args_parse(int argc, char** argv);

    /**
     * @return Returns the server address in the string format
     */
    std::string* get_server();

    /**
     * @return Returns the port to connect to
     */
    short get_port();

    /**
     * @return Returns the path to the authentication credentials file
     */
    std::string* get_auth_file();

    /**
     * @return Returns the path to the folder where the e-mails should be stored
     */
    std::string* get_out_dir();

    /**
     * @return Returns true if -T flag was set otherwise returns false
     */
    bool is_secure();

    /**
     * @return Returns true is -d flag was set, otherwise returns false
     */
    bool delete_flag();

    /**
     * @return Returns true is -n flag was set, otherwise returns false
     */
    bool new_flag();
private:

    //Server name (IP address)
    std::string* server;

    //Optional port number
    unsigned short port;

    //File containing credentials for SSL/TLS 
    std::string* cert_file;

    //Directory containing credentials file
    std::string* cert_dir;

    //Delete messages flag
    bool delete_msgs = false;

    //Only new messages
    bool only_new = false;

    //Compulsory file containing autharization data
    std::string* auth_file;

    //Compulsory output directory
    std::string* out_dir;

    //Turns on encryption of all communication (pop3s)
    bool secure_pop3s = false;

    //Establishes an unencrypted connection to the server and uses the STLS command
    bool secure_stls = false;
};
