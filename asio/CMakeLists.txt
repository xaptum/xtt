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

set(XTT_ASIO_SRC_FILES
        src/server_handshake.cpp
        src/asio_runner.cpp
        )

################################################################################
# Shared Libary
################################################################################
if(BUILD_SHARED_LIBS)
        add_library(xtt-asio ${XTT_ASIO_SRC_FILES})

        set_target_properties(xtt-asio PROPERTIES
                VERSION "${XTT_VERSION}"
                SOVERSION "${XTT_SOVERSION}"
        )

        target_include_directories(xtt-asio PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(xtt-asio
                PUBLIC
                xtt-cpp
                ${Boost_LIBRARIES}
              )

        install(TARGETS xtt-asio
                EXPORT xtt-targets
                RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
                LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        )
endif()

################################################################################
# Static Libary
################################################################################
if(BUILD_STATIC_LIBS)
        add_library(xtt-asio_static STATIC ${XTT_ASIO_SRC_FILES})

        set_target_properties(xtt-asio_static PROPERTIES
                OUTPUT_NAME "xtt-asio${STATIC_SUFFIX}"
                VERSION "${XTT_VERSION}"
                SOVERSION "${XTT_SOVERSION}"
        )

        target_include_directories(xtt-asio_static PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(xtt-asio_static
                PUBLIC
                xtt-cpp_static
                ${Boost_LIBRARIES}
              )

        install(TARGETS xtt-asio_static
                EXPORT xtt-targets
                RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
                LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        )
endif()

################################################################################
# Headers
################################################################################
install(FILES include/xtt-asio.hpp DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(DIRECTORY include/xtt-asio DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

################################################################################
# pkgconfig
################################################################################
configure_file(${PROJECT_SOURCE_DIR}/xtt-asio.pc.in xtt-asio.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/xtt-asio.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
