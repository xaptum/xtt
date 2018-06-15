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

set(XTT_CURRENT_PROGRAMS_BINARY_DIR ${CMAKE_BINARY_DIR}/bin/)

set(XTT_EXAMPLES_MAIN_FILES
        xtt_create_root.c
        xtt_client.c
        xtt_generate_certificate.c
        xtt_server.c
        )

foreach(main_file ${XTT_EXAMPLES_MAIN_FILES})
        get_filename_component(program_name ${main_file} NAME_WE)

        add_executable(${program_name} ${main_file})

        if(BUILD_SHARED_LIBS)
              target_link_libraries(${program_name} PRIVATE xtt sodium)
        else()
              target_link_libraries(${program_name} PRIVATE xtt_static sodium)
        endif()

        set_target_properties(${program_name} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY ${XTT_CURRENT_PROGRAMS_BINARY_DIR}
                )

        install(TARGETS ${program_name} DESTINATION ${CMAKE_INSTALL_BINDIR})
endforeach()
