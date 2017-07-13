#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "testhelpers.hpp"
#include "../HttpParser.hpp"

template<typename IterT>
http::request getRequestFromBigParser(IterT inputBegin, IterT inputEnd)
{
	http::request request;
	std::string body;
	bool done = false;

	auto callback = [&](const http::request_head &head, const char *bodyPart,
			std::size_t bodyPartLength, bool finished)
	{
		assert(!done);
		body.append(bodyPart, bodyPartLength);
		//std::cout << body.size() << std::endl;
		if (finished) {
			request.head(std::move(head));
			done = true;
		}
	};

	http::big_request_parser bigParser(callback);
	bigParser.feed(inputBegin, inputEnd);
	bigParser.feed_eof();

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

	request baselineRequest;
	RequestParser ordinaryParser([&baselineRequest](request&& r)
		{ baselineRequest = std::move(r); });
	ordinaryParser.feed(input, sizeof(input) - 1);
	ordinaryParser.feed_eof();

	assert(getRequestFromBigParser(sinput.begin(), sinput.end()) == baselineRequest);
	assert(getRequestFromBigParser(linput.begin(), linput.end()) == baselineRequest);

	bool exceptionThrown = false;
	try {
		auto callback =
				[](const request_head&, const char *, std::size_t bodyPartLength, bool) {};
		big_request_parser bigParser(callback);
		bigParser.set_max_headers_length(10);
		bigParser.feed(sinput.begin(), sinput.end());
	} catch (const request_headers_too_big &) {
		exceptionThrown = true;
	}
	assert(exceptionThrown);

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
