# Bifrost: A TFTP Server and Client in C


## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Building the Project](#building-the-project)
- [Usage](#usage)
  - [TFTP Server](#tftp-server)
  - [TFTP Client](#tftp-client)
  - [Test Scripts](#test-scripts)
- [License](#license)

## Overview

Bifrost is an educational implementation of the Trivial File Transfer Protocol (TFTP) in C. It includes both a TFTP server and a TFTP client, along with support for various option extension RFCs. This project demonstrates the core TFTP protocol as defined in [RFC 1350](https://datatracker.ietf.org/doc/html/rfc1350) and extends it with features from:

- **RFC 2347** – TFTP Option Extension
- **RFC 2348** – TFTP Block Size Option
- **RFC 2349** – TFTP Transfer Size Option
- **RFC 7440** - TFTP Window Size Option 

These extensions improve performance and flexibility, especially for large file transfers.

## Features

- **TFTP Server and Client:** Implements all basic TFTP operations:
  - Read Request (RRQ)
  - Write Request (WRQ)
  - DATA, ACK, and ERROR packets
- **Option Extensions:** Supports advanced TFTP options:
  - **RFC 2347:** Option extension mechanism
  - **RFC 2348:** Negotiation of block size up to 65464
  - **RFC 2349:** (Partially) Transfer size negotiation
  - **RFC 7440:** (Work in Progress) Window size negotiation
- **Block Number Rollover:** When block number reaches 65535 (UINT16_MAX) it resets to 0 allowing files larger than 32MB to be transferred. 
- **Dual-Stack Support:** Works on both IPv4 and IPv6 networks.
- **Robust Error Handling:** Provides comprehensive error codes and error management for various TFTP scenarios.

## Prerequisites

- **Compiler:** A standard C compiler (e.g., GCC)
- **Make:** GNU Make
- **Operating System:** POSIX-compliant system (e.g., Linux, macOS)
- **Root Privileges:** May be required for binding to well-known ports (e.g., port 69)

## Building the Project

Clone the repository and build the project using the provided Makefile, the compiled binaries are stored in the generated `bld/` folder

```bash
git clone https://github.com/yourusername/bifrost.git
cd bifrost
make clean
make release
```

## Usage

### TFTP Server

To start the TFTP server first change the working directory to bld and launch as below, by default the server binds to all interfaces (ipv4 and ipv6) and listens on port **6969**; you can use the port 69 with sudo priveleges. Default path for server root is /srv/tftp/.

```bash
./serv_tftp -i <ip_addr> -p <port num> -s <server root path>
```

The server supports RFC extensions for options negotiation as mentioned above.

### TFTP Client

Download a file from the TFTP server:
```bash
./client_tftp -g -l <local_save_path> -r <remote_filename> [options] <server_ip> 
```

Upload a file to the TFTP server:

```bash
./client_tftp -p -l <local_file_path> -r <remote_directory> [options] <server_ip>
```

Optional parameters include:

- `-b <block_size>`: Specify a custom block size (e.g., 8192 bytes)
- `-w <window_size>`: Specify the window size for TFTP option extension negotiation


## License

This project is licensed under the MIT License. See the `LICENSE` file for details.