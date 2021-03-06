#undef NDEBUG
#include <cassert>
#include <iostream>
#include "../http_parser.hpp"

int main()
{
    using namespace std;
    using namespace http;

    const std::string input =
            "POST /handleform HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "11; length is given in hex and this text should be ignored\r\n"
            "par1=koko+jumbo&p\r\n"
            "10\r\n"
            "ar2=kinematograf\r\n"
            "0\r\n"
            "LateHeader1: this example\r\n"
            "LateHeader2: consists of just two chunks\r\n"
            "\r\n";

    request_parser parser;
    parser.feed(input.cbegin(), input.cend());
    parser.feed_eof();
    assert(1 == parser.get_request_count());

    const request r = parser.pop_request();

    assert(HTTP_POST == r.method());
    assert(1 == r.http_version().major() && 1 == r.http_version().minor());
    assert("/handleform" == r.url());
    assert(5 == r.header_count());
    assert(r.has_header("Host"));
    assert(r.has_header("Content-Type"));
    assert(r.has_header("Transfer-Encoding"));
    assert(r.has_header("LateHeader1"));
    assert(r.has_header("LateHeader2"));
    assert("example.com" == r.get_header("Host"));
    assert("application/x-www-form-urlencoded" ==  r.get_header("Content-Type"));
    assert("chunked" == r.get_header("Transfer-Encoding"));
    assert("this example" == r.get_header("LateHeader1"));
    assert("consists of just two chunks" == r.get_header("LateHeader2"));
    assert("par1=koko+jumbo&par2=kinematograf" == r.body());

    cout << "If you can see this message, the test passed OK" << endl;
    return 0;
}
