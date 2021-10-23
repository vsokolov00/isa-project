# ISA - Network Applications and Network Administration
## POP3 client with the TLS support

### Application description
The `popcl` application is capable of downloading the e-mails from the given e-mail server via the POP3/POP3S protocol.
The application is fully functional on Linux, FreeBSD and macOS.

### Installation
Parameters of compilation are in `CMakeLists.txt` file, `Makefile` uses `CMake` to create the executable application.
`make` command will comile the `popcl` binary. `make clean` will delete all files and folders created during the compilation.

### Usage
popcl <server> [-p <port>] [-T|-S [-c <certfile>] [-C <certaddr>]] [-d] [-n] -a <auth_file> -o <out_dir>
  - The <server> name (IP address or domain name) to download the e-mails from is mandatory.
  - The -p option specifies the port number <port> on the server. If not specified the default port number will be used.
  - The -T parameter enables the encryption of all communication (POP3S), if the parameter is not specified, the unencrypted variant of the protocol will be used.
  - The -S parameter establishes an unencrypted connection to the server and switches to the encrypted protocol variant using the STLS command (RFC 2595).
  - The optional -c parameter defines the <certfile> certificate file, which is used to validate the SSL / TLS certificate submitted by the server (use only with the -T or -S parameter).
  - The optional -C parameter specifies the <certaddr> directory in which to search for certificates to be used to validate the SSL / TLS certificate submitted by the server. (Use only with the -T or -S parameter.)
  - When the -d parameter is used, a command is sent to the server to clear messages.
  - When using the -n parameter, only new messages will be downloaded.
  - The mandatory parameter -a <auth_file> specifies the file containing the credentials to log in to the specified mail server.
  - The mandatory parameter -o <out_dir> specifies the output directory <out_dir> in which the program should save the downloaded messages.
  
### Example
   ```bash
      ./popcl -T eva.fit.vutbr.cz -a ./eva_auth -o ./out_mail
      1156 e-mails were downloaded
  ```
  
### List of files
  ```bash
.
├── src
│   ├── popcl.cpp
│   ├── ArgumentsParser.cpp
│   ├── ArgumentsParser.hpp
│   ├── MessagesReceiver.cpp
│   └── MessagesReceiver.hpp
├── CMakeList.txt
├── Makefile
└── README.md
```
