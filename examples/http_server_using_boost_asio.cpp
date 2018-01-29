/* Based on http://www.boost.org/doc/libs/1_61_0/doc/html/boost_asio/example/cpp11/echo/async_tcp_echo_server.cpp */

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include "../http_parser.hpp"

using boost::asio::ip::tcp;
using namespace http;


class session : public std::enable_shared_from_this<session>
{
    static const size_t INPUT_BUF_LEN = 512;

private:
    tcp::socket    socket_;
    bool           keep_alive_               = true;
    char           input_buf_[INPUT_BUF_LEN];
    request_parser req_parser_;

public:
    session(tcp::socket socket)
        : socket_(std::move(socket)),
          req_parser_([this](request_parser&) { on_request_received(); }) {}

    void start() { do_read(); }

private:
    void do_read()
    {
        auto self(shared_from_this());
        auto read_callback =
                [this, self](boost::system::error_code ec, std::size_t length)
        {
            try {
                if (length > 0U) {
                    req_parser_.feed(input_buf_, length);
                }
                if (ec) {
                    req_parser_.feed_eof();
                } else if (keep_alive_) {
                    do_read();
                }
            } catch (const request_parse_error&) {
                do_write(
                        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 17\r\n\r\n400 Bad Request\r\n");
            }
        };
        socket_.async_read_some(
                boost::asio::buffer(input_buf_, INPUT_BUF_LEN), read_callback);
    }

    void do_write(std::string response)
    {
        auto self(shared_from_this());
        auto response_buffer = std::make_shared<std::string>(std::move(response));
        auto write_callback =
                [self, response_buffer](boost::system::error_code, std::size_t) {};
        // write_callback will keep response_buffer valid until the whole response is sent
        boost::asio::async_write(socket_, boost::asio::buffer(*response_buffer),
                write_callback);
    }

    void on_request_received()
    {
        request req = req_parser_.pop_request();
        keep_alive_ = req.keep_alive();
        const std::string ver = req.http_version().to_string();
        const std::string extra_headers = keep_alive_ ? "" : "Connection: close\r\n";
        if (req.method() != HTTP_GET) {
            do_write(
                    "HTTP/" + ver + " 405 Method Not Allowed\r\nAllow: GET\r\n" +
                    extra_headers + "Content-Type: text/plain\r\n"
                    "Content-Length: 24\r\n\r\n405 Method Not Allowed\r\n");
            return;
        }
        try {
            url_t url = parse_url(req.url());
            if ("/" == url.path) {
                do_write(
                        "HTTP/" + ver + " 200 OK\r\n" +
                        extra_headers + "Content-Type: text/plain\r\n"
                        "Content-Length: 15\r\n\r\nHello, World!\r\n");
            } else {
                do_write(
                        "HTTP/" + ver + " 404 Not Found\r\n" +
                        extra_headers + "Content-Type: text/plain\r\n"
                        "Content-Length: 15\r\n\r\n404 Not Found\r\n");
            }
        } catch (const url_parse_error&) {
            do_write(
                    "HTTP/" + ver + " 400 Bad Request\r\n" +
                    extra_headers + "Content-Type: text/plain\r\n"
                    "Content-Length: 31\r\n\r\n400 Bad Request (invalid url)\r\n");
        }
    }
};


class server
{
    tcp::acceptor acceptor_;
    tcp::socket   socket_;

public:
    server(boost::asio::io_service& io_service, short port)
        : acceptor_(io_service, tcp::endpoint(tcp::v4(), port)),
          socket_(io_service) { do_accept(); }

private:
    void do_accept()
    {
        auto accept_callback = [this](boost::system::error_code ec) {
            if (!ec) {
                std::make_shared<session>(std::move(socket_))->start();
            }
            do_accept();
        };
        acceptor_.async_accept(socket_, accept_callback);
    }
};


int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: http_server_using_boost_asio <port>\n";
        return 1;
    }
    const int port_num = std::atoi(argv[1]);

    try    {
        boost::asio::io_service io_service;
        server srv(io_service, port_num);
        io_service.run();
    } catch (const std::exception& e) {
        std::cerr << "Interrupted by exception: " << e.what() << "\n";
    }

    return 0;
}
