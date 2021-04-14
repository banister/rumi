cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(columbo VERSION 1.0)

file(GLOB_RECURSE SRC_FILES src/*.cpp)

find_package(fmt CONFIG REQUIRED)

add_executable(columbo  ${SRC_FILES})

target_link_libraries(columbo PRIVATE fmt::fmt)

target_include_directories(columbo PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
