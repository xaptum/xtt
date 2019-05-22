# XTT IoT security protocol

[![Release](https://img.shields.io/github/release/xaptum/xtt.svg)](https://github.com/xaptum/xtt/releases)
[![Build Status](https://travis-ci.org/xaptum/xtt.svg?branch=master)](https://travis-ci.org/xaptum/xtt)

XTT is a C implementation of the [XTT
protocol](https://xaptum.github.io/xtt-spec/) for securing Internet of
Things (IoT) network traffic.  It provides scalable identity
provisioning, device authentication, and data integrity and
confidentiality.

TODO: Actually briefly summarize protocol justification and features.

## Installation

`xtt` is available for the following distributions. It may also be
built from source.

### Debian (Stretch)

``` bash
# Install the Xaptum API repo GPG signing key.
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys c615bfaa7fe1b4ca

# Add the repository to your APT sources
echo "deb http://dl.bintray.com/xaptum/deb stretch main" > /etc/apt/sources.list.d/xaptum.list

# Install the library.
sudo apt-get install libxtt-dev
```

### Homebrew (MacOS)

``` bash
# Tap the Xaptum Homebrew repository.
brew tap xaptum/xaptum

# Install the library.
brew install xtt
```

## Installation from Source

### Build Dependencies

* CMake (version 3.0 or higher)
* A C99-compliant compiler

* [ECDAA](https://github.com/xaptum/ecdaa) (version 0.10.0 or higher)
* [libsodium](https://github.com/jedisct1/libsodium) (version 1.0.11 or higher)
* [xaptum-tpm](https://github.com/xaptum/xaptum-tpm) (version 0.5.0 or higher)
  * If building XTT with TPM support

### Building the Library

```bash
# Create a subdirectory to hold the build
mkdir -p build
cd build

# Configure the build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Build the library
cmake --build .

# Run the tests
ctest -V
```

### CMake Options

The following CMake configuration options are supported.

| Option               | Values         | Default    | Description                                            |
|----------------------|----------------|------------|--------------------------------------------------------|
| CMAKE_BUILD_TYPE     | Release        |            | With full optimizations.                               |
|                      | Debug          |            | With debug symbols.                                    |
|                      | RelWithDebInfo |            | With full optimizations and debug symbols.             |
|                      | Dev            |            | With warnings treated as errors and full optimizations.|
|                      | DevDebug       |            | With warnings treated as errors and debug symbols.     |
| CMAKE_INSTALL_PREFIX |                | /usr/local | The directory to install the library in.               |
| USE_TPM              | ON, OFF        | ON         | Build with support for using a TPM 2.0                 |
| BUILD_TOOL           | ON, OFF        | ON         | Build tool.                                            |
| BUILD_SHARED_LIBS    | ON, OFF        | ON         | Build shared libraries.                                |
| BUILD_STATIC_LIBS    | ON, OFF        | OFF        | Build static libraries.                                |
| BUILD_TESTING        | ON, OFF        | ON         | Build the test suite.                                  |
| STATIC_SUFFIX        | <string>       | <none>     | Appends a suffix to the static lib name.               |

### Installing

```bash
cd build
cmake --build . --target install
```

## Command Line Tool

If the `-DBUILD_TOOL=ON` CMake option is used during building,
the XTT tool will be built and placed in the `${CMAKE_BINARY_DIR}/tool` directory.

Example data for the `client` and the `server` can be found in their respective directories under `${xtt_root_directory}/data/`.

### Creating a Root
To create root configuration data, run:  
`xtt genkeypair -k root_keys.asn1.bin` to create a root key pair.  
`xtt genrootcert` to create a root certificate.  

### Provisioning a Server        
To create server configuration data under that root, run:
`xtt genkeypair -k server_keys.asn1.bin` to create a server key pair.
`xtt genservercert` to create a server certificate.  

### Running a Test Server  
The server executable can take the DAA Group Public Key and basename to use as parameter:  
(run `xtt runserver -h` for a full help on all available parameters):
```bash
xtt runserver -d <gpk file> -b <basename file>
```

The server will then listen on that port for incoming identity-provisioning
requests, service them sequentially (the server is single-threaded),
and output the agreed-upon identity information exchanged with the client.

### Running a Test Client  
The client executable can take the server's ID, DAA group public key, credentials, secret key, and basename to use as parameter:  
(run `xtt runclient -h` for a full help on all available parameters):
```bash
xtt runclient -d <gpk file> -c <credential file> -k <secret key file> -n <basename file>
```

The client will then initiate an identity-provisioning handshake with the server
listening on the given IP and port,
and output the agreed-upon identity information exchanged with that server.


# License
Copyright 2018 Xaptum, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
