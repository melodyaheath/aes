cmake_minimum_required(VERSION 3.12...3.16)
project(AESCrackme VERSION 1.0 LANGUAGES CXX)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    
    # Let's ensure -std=c++xx instead of -std=g++xx
    set(CMAKE_CXX_EXTENSIONS OFF)

    # Let's nicely support folders in IDE's
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()


add_subdirectory(src)
add_subdirectory(app)

option(PACKAGE_TESTS "Build the tests" ON)
if (CMAKE_BUILD_TYPE STREQUAL "Debug" AND PACKAGE_TESTS)
    enable_testing()
    include(GoogleTest)
    add_subdirectory(tests)
endif()