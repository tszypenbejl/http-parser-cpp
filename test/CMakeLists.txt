include_directories (${http_parser_cpp_SOURCE_DIR})
add_executable (test1 test1.cpp)
target_link_libraries(test1 http_parser)
