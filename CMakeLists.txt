cmake_minimum_required(VERSION 3.13)

project(ssl_cert_check)

set(CMAKE_CXX_STANDARD 20)

add_library(SSL_CERT_CHECK_LIBRARY STATIC
    ${CMAKE_SOURCE_DIR}/include/ssl_cert_check.cpp
    ${CMAKE_SOURCE_DIR}/include/ssl_cert_check.h
)

set_target_properties(SSL_CERT_CHECK_LIBRARY PROPERTIES OUTPUT_NAME "ssl_cert_check_library")

target_include_directories(SSL_CERT_CHECK_LIBRARY
        PRIVATE
            ${CMAKE_SOURCE_DIR}/third_party/asio/asio/include
)

if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0601)

    target_include_directories(SSL_CERT_CHECK_LIBRARY
        PRIVATE
            ${CMAKE_SOURCE_DIR}/third_party/openssl/include/
    )
    
    target_link_directories(SSL_CERT_CHECK_LIBRARY
        PUBLIC
            ${CMAKE_SOURCE_DIR}/lib
    )

    target_link_libraries(SSL_CERT_CHECK_LIBRARY
        PRIVATE
            libssl
            libcrypto
    )
else()

    target_link_libraries(SSL_CERT_CHECK_LIBRARY
        PRIVATE
            ssl
            crypto
            pthread
        )

endif()

add_executable(SSL_CERT_CHECK
    ${CMAKE_SOURCE_DIR}/src/main.cpp
)

target_include_directories(SSL_CERT_CHECK
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(SSL_CERT_CHECK
    PRIVATE
        SSL_CERT_CHECK_LIBRARY
)

set_target_properties(SSL_CERT_CHECK PROPERTIES OUTPUT_NAME "ssl_cert_check")

if(WIN32)

    file(GLOB OPENSSL_RUNTIME_LIBRARY 
        ${CMAKE_SOURCE_DIR}/lib/*.dll
        ${CMAKE_SOURCE_DIR}/lib/*.pdb
    )

    foreach(lib ${OPENSSL_RUNTIME_LIBRARY})
        add_custom_command(TARGET SSL_CERT_CHECK POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${lib} $<TARGET_FILE_DIR:SSL_CERT_CHECK>)
    endforeach()

endif()


