#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "testhelpers.hpp"
#include "../http_parser.hpp"

template<typename Iter>
http::request get_request_from_big_parser(Iter input_begin, Iter input_end)
{
    http::request request;
    std::string body;
    bool done = false;

    auto callback = [&](const http::request_head &head, const char *body_part,
            std::size_t body_part_length, bool finished)
    {
        assert(!done);
        body.append(body_part, body_part_length);
        if (finished) {
            request.head(std::move(head));
            done = true;
        }
    };

    http::big_request_parser big_parser(callback);
    big_parser.feed(input_begin, input_end);
    big_parser.feed_eof();

    assert(done);
    request.body(std::move(body));
    return request;
}

int main()
{
    using namespace std;
    using namespace http;

    char input[] =
            "POST /processform.cgi HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: multipart/form-data; boundary=--abcd1234\r\n"
            "Content-Length: 791\r\n"
            "\r\n"
            "----abcd1234\r\n"
            "Content-Disposition: form-data; name=\"text\"\r\n"
            "\r\n"
            "Short text entered into a text field.\r\n"
            "----abcd1234\r\n"
            "Content-Disposition: form-data; name=\"upl_file\"; filename=\"lorem.txt\"\r\n"
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
            "eleifend.\r\n"
            "----abcd1234--\r\n";

    std::string sinput = input;
    std::list<char> linput(sinput.begin(), sinput.end());

    request baseline_request;
    request_parser ordinary_parser([&baseline_request](request_parser& rp)
        { baseline_request = rp.pop_request(); });
    ordinary_parser.feed(input, sizeof(input) - 1);
    ordinary_parser.feed_eof();

    assert(get_request_from_big_parser(sinput.begin(), sinput.end()) == baseline_request);
    assert(get_request_from_big_parser(linput.begin(), linput.end()) == baseline_request);

    bool exception_thrown = false;
    try {
        auto callback =
                [](const request_head&, const char *, std::size_t body_part_length, bool) {};
        big_request_parser big_parser(callback);
        big_parser.set_max_headers_length(10);
        big_parser.feed(sinput.begin(), sinput.end());
    } catch (const request_headers_too_big &) {
        exception_thrown = true;
    }
    assert(exception_thrown);

    cout << "If you can see this message, the test passed OK" << endl;
    return 0;
}
