

file(GLOB AES_LIB_HEADERS CONFIGURE_DEPENDS "${AESCrackme_SOURCE_DIR}/includes/*.hpp")
file(GLOB AES_LIB_SOURCES CONFIGURE_DEPENDS "${AESCrackme_SOURCE_DIR}/src/*.cpp")
add_library(AESCrackme_library ${AES_LIB_HEADERS} ${AES_LIB_SOURCES})
target_compile_features(AESCrackme_library PUBLIC cxx_std_17)
target_include_directories(AESCrackme_library PUBLIC ../includes)





# IDEs should put the headers in a nice place
source_group(TREE "${AESCrackme_SOURCE_DIR}/include" PREFIX "Header Files" FILES ${AES_LIB_HEADERS})
