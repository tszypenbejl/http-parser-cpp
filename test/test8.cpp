#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "testhelpers.hpp"
#include "../HttpParser.hpp"

template<typename IterT>
http::Response getResponseFromBigParser(IterT inputBegin, IterT inputEnd)
{
	http::Response response;
	std::string body;
	bool done = false;

	auto callback = [&](const http::ResponseHead &resp, const char *bodyPart,
			std::size_t bodyPartLength, bool finished)
	{
		assert(!done);
		body.append(bodyPart, bodyPartLength);
		//std::cout << body.size() << std::endl;
		if (finished) {
			response.getHead() = resp;
			done = true;
		}
	};

	http::BigResponseParser bigParser(callback);
	bigParser.feed(inputBegin, inputEnd);
	bigParser.feedEof();

	assert(done);
	response.body = std::move(body);
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

	Response baselineResponse;
	ResponseParser ordinaryParser([&baselineResponse](Response&& r)
		{ baselineResponse = std::move(r); });
	ordinaryParser.feed(input, sizeof(input) - 1);
	ordinaryParser.feedEof();
	//cout << baselineResponse;

	assert(getResponseFromBigParser(sinput.begin(), sinput.end()) == baselineResponse);
	assert(getResponseFromBigParser(linput.begin(), linput.end()) == baselineResponse);

	bool exceptionThrown = false;
	try {
		auto callback =
				[](const ResponseHead &, const char *, std::size_t bodyPartLength, bool) {};
		BigResponseParser bigParser(callback);
		bigParser.setMaxHeadersLength(10);
		bigParser.feed(sinput.begin(), sinput.end());
	} catch (const response_headers_too_big &) {
		exceptionThrown = true;
	}
	assert(exceptionThrown);

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
