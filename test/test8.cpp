#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "testhelpers.hpp"
#include "../http_parser.hpp"

template<typename IterT>
http::response getResponseFromBigParser(IterT inputBegin, IterT inputEnd)
{
    http::response response;
    std::string body;
    bool done = false;

    auto callback = [&](const http::response_head &head, const char *bodyPart,
            std::size_t bodyPartLength, bool finished)
    {
        assert(!done);
        body.append(bodyPart, bodyPartLength);
        //std::cout << body.size() << std::endl;
        if (finished) {
            response.head(std::move(head));
            done = true;
        }
    };

    http::big_response_parser bigParser(callback);
    bigParser.feed(inputBegin, inputEnd);
    bigParser.feed_eof();

    assert(done);
    response.body(std::move(body));
    return response;
}

int main()
{
    using namespace std;
    using namespace http;

    char input[] =
            "HTTP/1.1 200 OK\r\n"
            "Date: Tue, 07 Jun 2016 06:36:18 -0500\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\r\n"
            "Sed leo ipsum, porttitor et odio vel, convallis tempor mi.\r\n"
            "Quisque dui ligula, posuere a tempor non, tincidunt id purus.\r\n"
            "Nunc in vulputate eros. Sed venenatis non nunc non porta.\r\n"
            "Praesent vestibulum rhoncus viverra. Donec mattis ac tortor ac\r\n"
            "euismod. Nam felis justo, bibendum quis ante quis, elementum\r\n"
            "ornare purus. Vivamus et fringilla orci, non volutpat dui. Duis\r\n"
            "tortor urna, ultrices a euismod sed, facilisis at diam.\r\n"
            "Pellentesque volutpat nunc vel erat egestas, quis semper orci\r\n"
            "eleifend.\r\n";

    std::string sinput = input;
    std::list<char> linput(sinput.begin(), sinput.end());

    response baseline_response;
    response_parser ordinaryParser([&baseline_response](response_parser& p)
            { baseline_response = p.pop_response(); });
    ordinaryParser.feed(input, sizeof(input) - 1);
    ordinaryParser.feed_eof();

    assert(getResponseFromBigParser(sinput.begin(), sinput.end()) == baseline_response);
    assert(getResponseFromBigParser(linput.begin(), linput.end()) == baseline_response);

    bool exceptionThrown = false;
    try {
        auto callback =
                [](const response_head &, const char *, std::size_t bodyPartLength, bool) {};
        big_response_parser bigParser(callback);
        bigParser.set_max_headers_length(10);
        bigParser.feed(sinput.begin(), sinput.end());
    } catch (const response_headers_too_big &) {
        exceptionThrown = true;
    }
    assert(exceptionThrown);

    cout << "If you can see this message, the test passed OK" << endl;
    return 0;
}
