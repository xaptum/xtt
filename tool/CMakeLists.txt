# Copyright 2018 Xaptum, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

################################################################################
# xtt
################################################################################
SET(TOOL_SRCS
        xtt.c
        parse_cli.c
        infocert.c
        server.c
        client.c)

if(USE_TPM)
    list(APPEND TOOL_SRCS read_nvram.c)
endif()

add_executable(xtt-tool ${TOOL_SRCS})
set_target_properties(xtt-tool PROPERTIES OUTPUT_NAME xtt)

target_link_libraries(xtt-tool PRIVATE sodium)
if(BUILD_SHARED_LIBS)
      target_link_libraries(xtt-tool PRIVATE xtt)
else()
      target_link_libraries(xtt-tool PRIVATE xtt_static)
endif()
install(TARGETS xtt-tool DESTINATION ${CMAKE_INSTALL_BINDIR})
