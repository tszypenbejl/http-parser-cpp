#!/bin/sh

g++ --std=c++11 -Wall -I$HOME/jshttp/include -L$HOME/jshttp/lib -Wl,-rpath,$HOME/jshttp/lib test.cpp -o test -lhttp_parser
