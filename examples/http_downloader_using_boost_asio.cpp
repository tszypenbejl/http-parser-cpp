/* based on http://www.boost.org/doc/libs/1_61_0/doc/html/boost_asio/example/cpp03/echo/blocking_tcp_echo_client.cpp */

#include <iostream>
#include <boost/asio.hpp>
#include "../HttpParser.hpp"

using boost::asio::ip::tcp;
using namespace http;

int main(int argc, char* argv[])
{
	try {
		if (argc != 2) {
			std::cerr << "Usage: " << argv[0] << " <URL>" << std::endl;
			return 1;
		}

		Url url;
		bool urlParsedOk = false;
		try {
			url = parseUrl(argv[1]);
			urlParsedOk = true;
		} catch (const UrlParseError&) {
		}
		if (!urlParsedOk || url.host.empty()) {
			std::cerr << "This does not appear to be a valid URL of a HTTP resource: "
			<< argv[1] << std::endl;
			return 1;
		}
		if (url.schema != "http") {
			std::cerr << "This program only supports plain HTTP." << std::endl;
			return 1;
		}
		if (0 == url.port) { // no port specified explicitly in the URL
			url.port = 80; // good as long as we only support http://
		}
		//std::cout << url << std::endl;

		std::ostringstream ss;
		ss << "GET " << url.path;
		if (!url.query.empty()) {
			ss << '?' << url.query;
		}
		ss << " HTTP/1.1\r\n"
				<< "Host: " << url.host << "\r\n"
				<< "Connection: close\r\n"
				<< "\r\n";
		const std::string request = ss.str();
		std::cout << request << std::endl;

		boost::asio::io_service ioService;

		tcp::resolver resolver(ioService);
		tcp::resolver::query query(tcp::v4(), url.host, std::to_string(url.port));
		tcp::resolver::iterator it = resolver.resolve(query);

		tcp::socket socket(ioService);
		std::cout << "Connecting to " << url.host << ':' << url.port << "... "
				<< std::flush;
		boost::asio::connect(socket, it);
		std::cout << "done\nSending request." << std::endl;
		boost::asio::write(socket, boost::asio::buffer(request));

		std::cout << "Reading response." << std::endl;
		// TODO: use BigResponseParser to save the response body to a file.
		// TODO: determine file name (may want to get response headers first
		char reply[2048];
		size_t reply_length = boost::asio::read(socket,
				boost::asio::buffer(reply, sizeof(reply)));
		std::cout << "Reply is:\n";
		std::cout.write(reply, reply_length);
		std::cout << "\n";
	} catch (const std::runtime_error &e) {
		std::cerr << "Interrupted by exception: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}