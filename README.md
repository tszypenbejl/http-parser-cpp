# http-parser-cpp
A quick and dirty c++ wrapper for https://github.com/nodejs/http-parser in just one header file.

This is a work in progress - not ready for production yet. See test/test1.cpp for usage.

License: BSD.

TODO:
* better tests
* chunking support,
* http response parser,
* handle protocol upgrades,
* provide wrapper for http_parser_parse_url(),
