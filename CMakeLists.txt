cmake_minimum_required(VERSION 3.18)

include(FetchContent)

project(sps3c C)

set(EXPAT_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(EXPAT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(EXPAT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(EXPAT_BUILD_TOOLS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    expat
    GIT_REPOSITORY https://github.com/libexpat/libexpat/
    GIT_TAG        R_2_7_4  # i.e. Git tag R_X_Y_Z
    SOURCE_SUBDIR  expat/
)

FetchContent_MakeAvailable(expat)

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
target_include_directories(mongoose PRIVATE mbedtls/include)
target_compile_definitions(mongoose PRIVATE MG_TLS=MG_TLS_MBED MG_ENABLE_MBEDTLS=1)

# Create executable
add_executable(sps3c src/main.c)

# Include directories
target_include_directories(sps3c PRIVATE src)
target_include_directories(sps3c PRIVATE mongoose)
target_include_directories(sps3c PRIVATE mbedtls/include)
target_include_directories(sps3c PRIVATE expat/include)

# Link libraries
target_link_libraries(sps3c PRIVATE -static)
target_link_libraries(sps3c PRIVATE mongoose mbedtls mbedx509 mbedcrypto expat::expat)
