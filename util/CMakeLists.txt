# Copyright 2017 Xaptum, Inc.
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
# xtt_generate_ecdsap256_keys
################################################################################
add_executable(xtt_generate_ecdsap256_keys xtt_generate_ecdsap256_keys.c)
if(BUILD_SHARED_LIBS)
      target_link_libraries(xtt_generate_ecdsap256_keys PRIVATE xtt)
else()
      target_link_libraries(xtt_generate_ecdsap256_keys PRIVATE xtt_static)
endif()
install(TARGETS xtt_generate_ecdsap256_keys DESTINATION ${CMAKE_INSTALL_BINDIR})

################################################################################
# xtt_wrap_keys_as_ASN1
################################################################################
add_executable(xtt_wrap_keys_as_ASN1 xtt_wrap_keys_as_ASN1.c)
if(BUILD_SHARED_LIBS)
      target_link_libraries(xtt_wrap_keys_as_ASN1 PRIVATE xtt)
else()
      target_link_libraries(xtt_wrap_keys_as_ASN1 PRIVATE xtt_static)
endif()
install(TARGETS xtt_wrap_keys_as_ASN1 DESTINATION ${CMAKE_INSTALL_BINDIR})
