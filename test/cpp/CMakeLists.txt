cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

set(CURRENT_TEST_BINARY_DIR ${CMAKE_BINARY_DIR}/testBin/)

add_executable(cpp_test cpp_test.cpp)

enable_language(CXX)

set_target_properties(cpp_test PROPERTIES COMPILE_OPTIONS -std=c++03)

if(BUILD_SHARED_LIBS)
  target_link_libraries(cpp_test PRIVATE xtt
    -fsanitize=address
    )
else()
  target_link_libraries(cpp_test PRIVATE xtt_static
    -fsanitize=address
    )
endif()

set_target_properties(cpp_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CURRENT_TEST_BINARY_DIR}
)

add_test(NAME cpp_test 
  COMMAND ${CURRENT_TEST_BINARY_DIR}/cpp_test
)
