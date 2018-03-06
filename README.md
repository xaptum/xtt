# XTT IoT security protocol

XTT is a C implementation of the
[XTT protocol](https://xaptum.github.io/xtt-spec/)
for securing Internet of Things (IoT) network traffic.
It provides scalable identity provisioning, device authentication, and data
integrity and confidentiality.

TODO: Actually briefly summarize protocol justification and features.

# Project Status
[![Build Status](https://travis-ci.org/xaptum/xtt.svg?branch=master)](https://travis-ci.org/xaptum/xtt)

## Requirements
- cmake version >= 3.0
- A C99-compliant compiler
- libsodium >= 1.0.8
- milagro-crypto-c >= 4.1.1
- [ecdaa](https://github.com/xaptum/ecdaa) >= 0.7.0
  - Requires header files (e.g. "dev" package)
- [xaptum-tpm](https://github.com/xaptum/xaptum-tpm) >= 0.4.0
  - Requires header files (e.g. "dev" package)

## Building the Library

`XTT` uses CMake as its build system.

```bash
# Create the build directory
mkdir build
cd build

# Generate the Makefiles
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Compile the code
cmake --build .

# Run the tests
ctest -V
```

In addition to the standard CMake options the following configuration
options and variables are supported.

### Static vs Shared Libary
If `BUILD_SHARED_LIBS` is set, the shared library is built. If
`BUILD_STATIC_LIBS` is set, the static library is built. If both are
set, both libraries will be built.  If neither is set, the static
library will be built.

### Static Library Name
`STATIC_SUFFIX`, if defined, will be appended to the static library
name.  For example,

```bash
cmake .. -DBUILD_STATIC_LIBS=ON -DSTATIC_SUFFIX=_static
cmake --build .
```

will create a static library named `libxtt_static.a`.

### Force Position Independent Code (-fPIC)
Set the standard CMake variable `CMAKE_POSITION_INDEPENDENT_CODE` to
`ON` to force compilation with `-fPIC` for static libraries.  The
default is `OFF` for static libraries and `ON` for shared libraries.

### Disable Building of Tests
Set the standard CMake variable `BUILD_TESTING` to `OFF` to disable
the building of tests.  The default value is `ON`.

## Installation

CMake creates a target for installation.

```bash
cd build
cmake --build . --target install
```

Set the `CMAKE_INSTALL_PREFIX` variable when configuring the build to
modify the installation location.


## Usage
```
#include <xtt.h>
```
TODO: Add simple client and server source code

### Example Programs
If the `-DBUILD_EXAMPLES=ON` CMake option is used during building,
example client and server executables will be built and placed
in the `${CMAKE_BINARY_DIR}/bin` directory.
Example configuration data is also provided in the `examples/data`
directory.

#### Server
To run the example server, first copy the necessary example data
into the working directory:
```bash
cp ${xtt_root_directory}/examples/data/server/* .
```

The server executable takes the TCP port to use as parameter:
```bash
xtt_server 4444
```

The server will then listen on that port for incoming identity-provisioning
requests, service them sequentially (the server is single-threaded),
and output the agreed-upon identity information exchanged with the client.

#### Client
To run the example client, first copy the necessary example data
into the working directory:
```bash
cp ${xtt_root_directory}/examples/data/client/* .
```

The client executable takes the `xtt_suite_spec` to use
(run the executable with no arguments to see what the options are)
and the IP and port of the server as parameters:
```bash
xtt_client 1 127.0.0.1 4444
```
(a suite_spec value of `1` indicates `XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512`).

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
