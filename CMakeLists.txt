cmake_minimum_required(VERSION 3.15)
project(list_users)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(list_users src/list_users.cpp)

if(MSVC)
    target_compile_options(list_users PRIVATE /W4)
else()
    target_compile_options(list_users PRIVATE -Wall -Wextra -Wpedantic)
endif()
