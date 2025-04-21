cmake_minimum_required(VERSION 3.12)
project(TinyAesPackageTest C CXX)

add_executable(example ${CMAKE_SOURCE_DIR}/test.c)
add_executable(example_cpp ${CMAKE_SOURCE_DIR}/test.cpp)

target_link_libraries(example PRIVATE tiny-aes)
target_link_libraries(example_cpp PRIVATE tiny-aes)

add_test(NAME C_Test COMMAND example)
add_test(NAME Cpp_Test COMMAND example_cpp)