cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

macro(add_test_case case_file)
  get_filename_component(case_name ${case_file} NAME_WE)

  add_executable(${case_name} ${case_file})

  if(BUILD_SHARED_LIBS)
    target_link_libraries(${case_name} PRIVATE xtt
            sodium
            ${ECDAA_LIBRARIES}
            ${XAPTUM_TPM_LIBRARIES})
  else()
    target_link_libraries(${case_name} PRIVATE xtt_static
            sodium
            ${ECDAA_LIBRARIES}
            ${XAPTUM_TPM_LIBRARIES})
  endif()

  target_include_directories(${case_name}
    PRIVATE ${PROJECT_SOURCE_DIR}/include/
  )

  set_target_properties(${case_name} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CURRENT_TEST_BINARY_DIR}
  )

  add_test(NAME ${case_name} 
    COMMAND ${CURRENT_TEST_BINARY_DIR}/${case_name}
  )
endmacro()

if(BUILD_TESTING)
  set(CURRENT_TEST_BINARY_DIR ${CMAKE_BINARY_DIR}/testBin/)

  file(GLOB_RECURSE TEST_SRCS "*.c")
  foreach(case_file ${TEST_SRCS})
    add_test_case(${case_file})
  endforeach()

endif()
