cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(rumi VERSION 1.0)

file(GLOB_RECURSE SRC_FILES src/*.cpp)

find_package(fmt CONFIG REQUIRED)

add_executable(rumi  ${SRC_FILES})

target_link_libraries(rumi PRIVATE fmt::fmt bsm)

target_include_directories(rumi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
