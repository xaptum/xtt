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
 #ifndef XTT_UTIL_FILE_IO_H
 #define XTT_UTIL_FILE_IO_H
 #pragma once

 #ifdef __cplusplus
 extern "C" {
 #endif

 #include <fcntl.h>
 #include <stddef.h>

 #define KEY_PERMISSION     0600
 #define CERT_PERMISSION    0644

/*
 * Writes given byte-string to the given file with a given permission level.
 *
 * Returns:
 * 'bytes_to_write' on success
 * SAVE_TO_FILE_ERROR on failure
*/
int xtt_save_to_file(unsigned char *buffer, size_t bytes_to_write, const char *filename, mode_t permission);

/*
 * Wrapper for xtt_save_to_file using KEY_PERMISSION level.
 * 
 * Returns:
 * 'bytes_to_write' on success
 * SAVE_TO_FILE_ERROR on failure
*/
int xtt_save_key_to_file(unsigned char *buffer, size_t bytes_to_write, const char *filename);

/*
 * Wrapper for xtt_save_to_file using CERT_PERMISSION level.
 * 
 * Returns:
 * 'bytes_to_write' on success
 * SAVE_TO_FILE_ERROR on failure
*/
int xtt_save_cert_to_file(unsigned char *buffer, size_t bytes_to_write, const char *filename);

/*
 * Read at-most `bytes_to_read` bytes from the given file.
 *
 * Reads until `bytes_to_read` bytes have been read, or until `EOF`, whichever comes first.
 *
 * Returns:
 * Number of bytes read into `buffer` on success
 * READ_FROM_FILE_ERROR on failure
*/
int xtt_read_from_file(const char *filename, unsigned char *buffer, size_t bytes_to_read);

#ifdef __cplusplus
}
#endif

#endif
