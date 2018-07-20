/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/
 
#ifndef NETWORKARRAY_H
#define NETWORKARRAY_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

 #include "test-utils.h"
 #include <string.h>


struct network_helper{
    unsigned char array[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
    unsigned char* head;
    size_t filled;
};

void setupNetwork(struct network_helper* network){
    network->head= network->array;
    network->filled= 0;
}

void read_bytes(struct network_helper* network, size_t numbytes, unsigned char* io_ptr) {
    TEST_ASSERT(network->filled >= numbytes);
    memcpy(io_ptr, network->head, numbytes);
    network->head+=numbytes;
    network->filled-=numbytes;
}

void write_bytes(struct network_helper* network, size_t numbytes, unsigned char* io_ptr) {
    TEST_ASSERT(network->filled+numbytes <= sizeof(network->array));
    memcpy(network->head, io_ptr, numbytes);
    network->filled += numbytes;
}

void clear_bytes(struct network_helper* network){
    TEST_ASSERT(network->filled == 0);
    network->head = network->array;
    network->filled = 0;
}


#ifdef __cplusplus
}
#endif

#endif
