add_subdirectory("${PROJECT_SOURCE_DIR}/extern/googletest" "extern/googletest")

mark_as_advanced(
    BUILD_GMOCK BUILD_GTEST BUILD_SHARED_LIBS
    gmock_build_tests gtest_build_samples gtest_build_tests
    gtest_disable_pthreads gtest_force_shared_crt gtest_hide_internal_symbols
)

find_package(OpenSSL COMPONENTS Crypto REQUIRED)

add_executable(aes_test aes_external_tests.cpp aes_internal_tests.cpp)
target_link_libraries(aes_test gtest gmock gtest_main OpenSSL::Crypto AESCrackme_library)

gtest_discover_tests(aes_test)
set_target_properties(aes_test PROPERTIES FOLDER tests)
