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
