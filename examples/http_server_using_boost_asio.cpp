/* Based on http://www.boost.org/doc/libs/1_61_0/doc/html/boost_asio/example/cpp11/echo/async_tcp_echo_server.cpp */

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include "../HttpParser.hpp"

using boost::asio::ip::tcp;
using namespace http;

class Session: public std::enable_shared_from_this<Session>
{
	static const size_t inputBufLen = 512;

private:
	tcp::socket socket;
	char inputBuf[inputBufLen];
	RequestParser reqParser;

public:
	Session(tcp::socket socket)
		: socket(std::move(socket)),
			reqParser([this](Request&& r) { onRequestReceived(r); }) {}

	void start() { doRead(); }

private:
	void doRead()
	{
		auto self(shared_from_this());
		auto readCallback =
				[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (ec) {
				return;
			}
			try {
				reqParser.feed(inputBuf, length);
				doRead();
			} catch (const RequestParseError&) {
				doWrite(
						"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
						"Content-Type: text/plain\r\n"
						"Content-Length: 17\r\n\r\n400 Bad Request\r\n");
			}
		};
		socket.async_read_some(
				boost::asio::buffer(inputBuf, inputBufLen), readCallback);
	}

	void doWrite(const std::string response)
	{
		auto self(shared_from_this());
		auto responseBuffer = std::make_shared<std::string>(std::move(response));
		auto writeCallback =
				[self, responseBuffer](boost::system::error_code, std::size_t) {};
		// writeCallback will keep responseBuffer valid until the whole response is sent
		boost::asio::async_write(socket, boost::asio::buffer(*responseBuffer),
				writeCallback);
	}

	void onRequestReceived(Request& req)
	{
		if (req.type != HTTP_GET) {
			doWrite(
					"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\n"
					"Content-Type: text/plain\r\n"
					"Content-Length: 24\r\n\r\n405 Method Not Allowed\r\n");
			return;
		}
		try {
			Url url = parseUrl(req.url);
			if ("/" == url.path) {
				doWrite(
						"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
						"Content-Length: 15\r\n\r\nHello, World!\r\n");
			} else {
				doWrite(
						"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
						"Content-Length: 15\r\n\r\n404 Not Found\r\n");
			}
		} catch (const UrlParseError&) {
			doWrite(
					"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
					"Content-Length: 31\r\n\r\n400 Bad Request (invalid url)\r\n");
		}
	}
};

class Server
{
	tcp::acceptor acceptor;
	tcp::socket socket;

public:
	Server(boost::asio::io_service& io_service, short port)
		: acceptor(io_service, tcp::endpoint(tcp::v4(), port)),
			socket(io_service) { doAccept(); }

private:
	void doAccept()
	{
		auto acceptCallback = [this](boost::system::error_code ec) {
			if (!ec) {
				std::make_shared<Session>(std::move(socket))->start();
			}
			doAccept();
		};
		acceptor.async_accept(socket, acceptCallback);
	}
};

int main(int argc, char* argv[])
{
	if (argc != 2) {
		std::cerr << "Usage: http_server_using_boost_asio <port>\n";
		return 1;
	}
	const int portNum = std::atoi(argv[1]);

	try	{
		boost::asio::io_service ioService;
		Server server(ioService, portNum);
		ioService.run();
	} catch (const std::exception& e) {
		std::cerr << "Interrupted by exception: " << e.what() << "\n";
	}
	return 0;
}
