#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "testhelpers.hpp"
#include "../http_parser.hpp"

template<typename Iter>
http::response get_response_from_big_parser(Iter input_begin, Iter input_end)
{
    http::response response;
    std::string body;
    bool done = false;

    auto callback = [&](const http::response_head &head, const char *body_part,
            std::size_t body_part_length, bool finished)
    {
        assert(!done);
        body.append(body_part, body_part_length);
        if (finished) {
            response.head(std::move(head));
            done = true;
        }
    };

    http::big_response_parser big_parser(callback);
    big_parser.feed(input_begin, input_end);
    big_parser.feed_eof();

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
    response_parser ordinary_parser([&baseline_response](response_parser& p)
            { baseline_response = p.pop_response(); });
    ordinary_parser.feed(input, sizeof(input) - 1);
    ordinary_parser.feed_eof();

    assert(get_response_from_big_parser(sinput.begin(), sinput.end()) == baseline_response);
    assert(get_response_from_big_parser(linput.begin(), linput.end()) == baseline_response);

    bool exception_thrown = false;
    try {
        auto callback =
                [](const response_head &, const char *, std::size_t body_part_length, bool) {};
        big_response_parser big_parser(callback);
        big_parser.set_max_headers_length(10);
        big_parser.feed(sinput.begin(), sinput.end());
    } catch (const response_headers_too_big &) {
        exception_thrown = true;
    }
    assert(exception_thrown);

    cout << "If you can see this message, the test passed OK" << endl;
    return 0;
}
