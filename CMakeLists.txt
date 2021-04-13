cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "out/")

project(columbo VERSION 1.0)

file(GLOB_RECURSE SRC_FILES src/*.cpp)

add_executable(columbo  ${SRC_FILES})

target_include_directories(columbo PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)



