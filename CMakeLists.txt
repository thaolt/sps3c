cmake_minimum_required(VERSION 3.10)
project(sps3c C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add subdirectories for dependencies
add_definitions(-DMBEDTLS_AS_SUBPROJECT)
option(ENABLE_PROGRAMS "" OFF)
option(ENABLE_TESTING "" OFF)

add_subdirectory(mbedtls)

# mongoose library
add_library(mongoose STATIC mongoose/mongoose.c)
target_include_directories(mongoose PRIVATE mongoose)

# Create executable
add_executable(sps3c src/main.c)

# Include directories
target_include_directories(sps3c PRIVATE src)
target_include_directories(sps3c PRIVATE mongoose)
target_include_directories(sps3c PRIVATE mbedtls/include)

# Link libraries
target_link_libraries(sps3c PRIVATE -static)
target_link_libraries(sps3c PRIVATE mongoose mbedtls mbedx509 mbedcrypto)
