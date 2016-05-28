cmake_minimum_required (VERSION 2.8)

project (http-parser-cpp C CXX)

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckIncludeFile)
check_include_file(http_parser.h HAVE_HTTP_PARSER_INCLUDE ${CMAKE_CXX_FLAGS})
include(CheckLibraryExists)
check_library_exists(http_parser http_parser_init "" HAVE_HTTP_PARSER_LIB)
if (NOT (HAVE_HTTP_PARSER_INCLUDE AND HAVE_HTTP_PARSER_LIB))
	message(FATAL_ERROR "http_parser library not available, you may need to adjust CXXFLAGS and LDFLAGS")
endif()

add_subdirectory(test)
add_subdirectory(examples)
