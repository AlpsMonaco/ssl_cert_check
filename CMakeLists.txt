cmake_minimum_required(VERSION 3.13)

project(ssl_cert_check)

set(CMAKE_CXX_STANDARD 17)

IF(NOT EXISTS "${CMAKE_SOURCE_DIR}/third_party/async_dns_resolver/third_party/c-ares/CMakeLists.txt")
    message(FATAL_ERROR "c-ares not exist\nplease run \"git submodule update --init --recursive\"")
ENDIF()

add_library(ssl_cert_check_library STATIC
    ${CMAKE_SOURCE_DIR}/include/ssl_cert_check.cpp
    ${CMAKE_SOURCE_DIR}/include/ssl_cert_check.h
)

target_include_directories(ssl_cert_check_library
    PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/asio/asio/include
)

add_subdirectory(third_party/async_dns_resolver)

if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0601)

    target_include_directories(ssl_cert_check_library
        PRIVATE
            ${CMAKE_SOURCE_DIR}/third_party/openssl/include/
    )
    
    target_link_directories(ssl_cert_check_library
        PUBLIC
            ${CMAKE_SOURCE_DIR}/lib
    )

    target_link_libraries(ssl_cert_check_library
        PRIVATE
            libssl
            libcrypto
            dns_resolve::lib
    )
else()

    target_link_libraries(ssl_cert_check_library
        PRIVATE
            ssl
            crypto
            pthread
            dns_resolve::lib
        )

endif()

add_executable(ssl_cert_check
    ${CMAKE_SOURCE_DIR}/src/main.cpp
)

target_include_directories(ssl_cert_check
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(ssl_cert_check
    PRIVATE
        ssl_cert_check_library
)

if(WIN32)

    file(GLOB OPENSSL_RUNTIME_LIBRARY 
        ${CMAKE_SOURCE_DIR}/lib/*.dll
        ${CMAKE_SOURCE_DIR}/lib/*.pdb
    )

    foreach(lib ${OPENSSL_RUNTIME_LIBRARY})
        add_custom_command(TARGET ssl_cert_check POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${lib} $<TARGET_FILE_DIR:ssl_cert_check>)
    endforeach()

endif()

add_custom_command(TARGET ssl_cert_check POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/domains.txt $<TARGET_FILE_DIR:ssl_cert_check>)

add_executable(network_test
    ${CMAKE_SOURCE_DIR}/include/tests/network_test.cpp
)

target_include_directories(network_test
        PRIVATE
            ${CMAKE_SOURCE_DIR}/third_party/asio/asio/include
)

if(WIN32)
else()
target_link_libraries(network_test
    PRIVATE
        pthread
)
endif()