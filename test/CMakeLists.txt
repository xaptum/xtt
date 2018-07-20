cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

function(add_test_case case_file test_args)
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

  if(test_args)
      foreach(test_arg ${test_args})
        add_test(NAME "${case_name}_${test_arg}"
          COMMAND "${CURRENT_TEST_BINARY_DIR}/${case_name}" ${test_arg}
        )
      endforeach()
  else()
      add_test(NAME ${case_name}
        COMMAND ${CURRENT_TEST_BINARY_DIR}/${case_name}
      )
  endif()
endfunction()

set(CURRENT_TEST_BINARY_DIR ${CMAKE_BINARY_DIR}/testBin/)

add_test_case("wrapper_sanity-test.c" "")
add_test_case("integration_test.c" "1;2;3;4")
add_test_case("certificate_test.c" "")
