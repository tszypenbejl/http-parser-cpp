# http-parser-cpp
A quick and dirty c++ wrapper for https://github.com/nodejs/http-parser in just one header file.

This is a work in progress - not ready for production yet. See test.cpp for usage.

License: BSD.

TODO:
* refactor class names,
* better tests, use CMake to build test program(s)
* chunking support,
* http response parser,
* handle protocol upgrades,
* provide wrapper for http_parser_parse_url(),
