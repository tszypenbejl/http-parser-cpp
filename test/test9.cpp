#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "testhelpers.hpp"
#include "../HttpParser.hpp"

template<typename IterT>
http::Request getRequestFromBigParser(IterT inputBegin, IterT inputEnd)
{
	http::Request request;
	std::string body;
	bool done = false;

	auto callback = [&](const http::Request &resp, const char *bodyPart,
			std::size_t bodyPartLength, bool finished)
	{
		assert(!done);
		body.append(bodyPart, bodyPartLength);
		//std::cout << body.size() << std::endl;
		if (finished) {
			request = resp;
			done = true;
		}
	};

	http::BigRequestParser bigParser(callback);
	bigParser.feed(inputBegin, inputEnd);
	bigParser.feedEof();

	assert(done);
	request.body = std::move(body);
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

	Request baselineRequest;
	RequestParser ordinaryParser([&baselineRequest](Request&& r)
		{ baselineRequest = std::move(r); });
	ordinaryParser.feed(input, sizeof(input) - 1);
	ordinaryParser.feedEof();

	assert(getRequestFromBigParser(sinput.begin(), sinput.end()) == baselineRequest);
	assert(getRequestFromBigParser(linput.begin(), linput.end()) == baselineRequest);

	bool exceptionThrown = false;
	try {
		auto callback =
				[](const Request &, const char *, std::size_t bodyPartLength, bool) {};
		BigRequestParser bigParser(callback);
		bigParser.setMaxHeadersLength(10);
		bigParser.feed(sinput.begin(), sinput.end());
	} catch (const RequestHeadersTooBig &) {
		exceptionThrown = true;
	}
	assert(exceptionThrown);

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
