#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "testhelpers.hpp"
#include "../http_parser.hpp"

int main()
{
    using namespace std;
    using namespace http;

    request_parser parser;

    char input[] = "GET /formhandler?par1=koko+jumbo&par2=kinematograf HTTP/1.1\r\nHost: example.com\r\n\r\n";
    std::string sinput(input);
    std::vector<char> vinput(sinput.begin(), sinput.end());
    std::list<char> linput(vinput.begin(), vinput.end());

    parser.feed(input, sizeof(input) - 1);
    parser.feed(input, input + sizeof(input) - 1);
    parser.feed(sinput.cbegin(), sinput.cend());
    parser.feed(vinput.cbegin(), vinput.cend());
    parser.feed(linput.cbegin(), linput.cend());
    parser.feed_eof();

    std::vector<request> parsed_requests;
    while (parser.get_request_count() > 0U) {
        parsed_requests.push_back(parser.pop_request());
    }
    assert(parsed_requests.size() == 5);
    assert(parsed_requests.at(0) == parsed_requests.at(1));
    assert(parsed_requests.at(0) == parsed_requests.at(2));
    assert(parsed_requests.at(0) == parsed_requests.at(3));
    assert(parsed_requests.at(0) == parsed_requests.at(4));

    const request& r = parsed_requests.front();
    assert(HTTP_GET == r.method());
    assert(1 == r.http_version().major() && 1 == r.http_version().minor());
    assert("/formhandler?par1=koko+jumbo&par2=kinematograf" == r.url());
    assert(1 == r.header_count());

    assert(r.has_header("Host"));
    assert(r.has_header("HOST"));
    assert(r.has_header("host"));
    assert(r.has_header("hOsT"));
    assert("example.com" == r.get_header("host"));
    assert("example.com" == r.get_header("host", "value-if-not-found"));
    assert(!r.has_header("Content-Type"));
    assert("text/plain" == r.get_header("Content-Type", "text/plain"));
    bool headerNotFoundErrorOccurred = false;
    try {
        (void) r.get_header("Content-Type");
    } catch (const header_not_found_error&) {
        //cerr << e.what() << endl;
        headerNotFoundErrorOccurred = true;
    }
    assert(headerNotFoundErrorOccurred);

    cout << "If you can see this message, the test passed OK" << endl;
    return 0;
}
