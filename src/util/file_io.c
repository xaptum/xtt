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
 #include <stdint.h>
 #include <stdio.h>
 #include <xtt/util/file_io.h>
 #include <xtt/util/util_errors.h>

 int xtt_save_to_file(unsigned char *buffer, size_t bytes_to_write, const char *filename)
 {
     FILE *file_ptr = fopen(filename, "wb");
     int ret = 0;
     int close_ret = 0;

     if (NULL == file_ptr){
         return SAVE_TO_FILE_ERROR;
     }

     size_t bytes_written = fwrite(buffer, 1, bytes_to_write, file_ptr);

     if (bytes_to_write != bytes_written) {
         ret = SAVE_TO_FILE_ERROR;
         goto cleanup;
     }

     ret = (int) bytes_written;

cleanup:
     close_ret = fclose(file_ptr);
     if (0 != close_ret) {
        ret = SAVE_TO_FILE_ERROR;
     }
     return ret;
 }

 int xtt_read_from_file(const char *filename, unsigned char *buffer, size_t bytes_to_read)
 {
     FILE *file_ptr = fopen(filename, "rb");
     int ret = 0;
     int close_ret = 0;

     if (NULL == file_ptr){
         return READ_FROM_FILE_ERROR;
     }
     size_t bytes_read = fread(buffer, 1, bytes_to_read, file_ptr);
     if (bytes_to_read != bytes_read && !feof(file_ptr)) {
        ret = READ_FROM_FILE_ERROR;
        goto cleanup;
     }

     ret = (int)bytes_read;

cleanup:
     close_ret = fclose(file_ptr);
     if (0 != close_ret) {
         ret = READ_FROM_FILE_ERROR;
     }
     return ret;

 }
