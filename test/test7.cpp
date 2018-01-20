#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "../http_parser.hpp"

int main()
{
    using namespace std;
    using namespace http;

    char input1[] =
            "HTTP/1.1 200 OK\r\n"
            "Date: Tue, 07 Jun 2016 05:16:11 -0500\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 15\r\n"
            "\r\n"
            "Hello, World!\r\n";

    char input2[] =
            "HTTP/1.1 200 OK\r\n"
            "Date: Tue, 07 Jun 2016 05:16:11 -0500\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 60\r\n"
            "\r\n"
            "Hello, World!\r\n"
            "Hello, World!\r\n"
            "Hello, World!\r\n"
            "Hello, World!\r\n";

    std::string sinput;
    sinput.append(input1);
    sinput.append(input2);
    std::list<char> linput(sinput.begin(), sinput.end());

    unsigned responses_parsed = 0;
    bool exception_thrown = false;

    auto response_consumer = [&responses_parsed] (response_parser&) -> void { ++responses_parsed; };

    response_parser sparser(response_consumer);
    response_parser lparser(response_consumer);

    sparser.set_max_response_length(sizeof(input1) - 1);
    lparser.set_max_response_length(sizeof(input1) - 1);

    try {
        sparser.feed(sinput.cbegin(), sinput.cend());
    } catch (const response_too_big&) {
        exception_thrown = true;
    }

    assert(1 == responses_parsed);
    assert(exception_thrown);

    responses_parsed = 0;
    exception_thrown = false;

    try {
        lparser.feed(linput.cbegin(), linput.cend());
    } catch (const response_too_big&) {
        exception_thrown = true;
    }
    
    assert(1 == responses_parsed);
    assert(exception_thrown);

    cout << "If you can see this message, the test passed OK" << endl;
    return 0;
}
