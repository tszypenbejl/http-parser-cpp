#pragma once

#include <http_parser.h>
// #include <iostream> // TODO: remove
#include <stdexcept>
#include <string>
#include <map>
#include <sstream>
#include <deque>
#include <type_traits>
#include <functional>
#include <iterator>
#include <cassert>

namespace http {

class Request;

using Headers = std::map<std::string, std::string>;
using RequestConsumer = std::function<void(Request&&)>;

namespace detail {

/*
 * TODO: Perhaps it would be possible to define a template:
 * template<typename ParserT>
 * struct Callbacks { ... };
 * and get rid of the virtual methods from the Parser class.
 */
struct Callbacks
{
	static int onMessageBegin(http_parser* p);
	static int onUrl(http_parser* p, const char *data, size_t length);
	static int onStatus(http_parser* p, const char *data, size_t length);
	static int onHeaderField(http_parser* p, const char *data, size_t length);
	static int onHeaderValue(http_parser* p, const char *data, size_t length);
	static int onHeadersComplete(http_parser* p);
	static int onBody(http_parser* p, const char *data, size_t length);
	static int onMessageComplete(http_parser* p);
	static int onChunkHeader(http_parser* p);
	static int onChunkComplete(http_parser* p);
};

struct ParserSettings
{
	http_parser_settings s;

public:
	static ParserSettings& get()
	{
		static ParserSettings instance;
		return instance;
	}

	ParserSettings(const ParserSettings&) = delete;
	ParserSettings(ParserSettings&&) = delete;

private:
	ParserSettings()
	{
		http_parser_settings_init(&s);
		s.on_message_begin = &Callbacks::onMessageBegin;
		s.on_url = &Callbacks::onUrl;
		s.on_status = &Callbacks::onStatus;
		s.on_header_field = &Callbacks::onHeaderField;
		s.on_header_value = &Callbacks::onHeaderValue;
		s.on_headers_complete = &Callbacks::onHeadersComplete;
		s.on_body = &Callbacks::onBody;
		s.on_message_complete = &Callbacks::onMessageComplete;
		s.on_chunk_header = &Callbacks::onChunkHeader;
		s.on_chunk_complete = &Callbacks::onChunkComplete;
	}
};

class HeaderAssembler
{
	Headers &headers;
	std::string currentHeaderField;
	std::string currentHeaderValue;
	bool currentHeaderFieldComplete = false;

public:
	HeaderAssembler(Headers &headers): headers(headers) {}
	HeaderAssembler(const HeaderAssembler&) = delete;
	HeaderAssembler(HeaderAssembler&&) = delete;
	HeaderAssembler& operator=(const HeaderAssembler&) = delete;
	HeaderAssembler& operator=(HeaderAssembler&&) = delete;

	void reset()
	{
		currentHeaderField.clear();
		currentHeaderValue.clear();
		currentHeaderFieldComplete = false;
	}

	void onHeaderField(const char *data, std::size_t length)
	{
		if (currentHeaderFieldComplete) {
			onSingleHeaderComplete();
		}
		currentHeaderField.append(data, length);
	}

	void onHeaderValue(const char *data, std::size_t length)
	{
		currentHeaderValue.append(data, length);
		currentHeaderFieldComplete = true;
	}

	void onHeadersComplete()
	{
		onSingleHeaderComplete();
	}

private:
	void onSingleHeaderComplete()
	{
		std::string& headerValue = headers[currentHeaderField];
		if (headerValue.empty()) {
			headerValue = std::move(currentHeaderValue);
		} else if (!currentHeaderValue.empty()) {
			headerValue.reserve(1 + currentHeaderValue.size());
			headerValue.append(",");
			headerValue.append(currentHeaderValue);
		}
		currentHeaderField.clear();
		currentHeaderValue.clear();
		currentHeaderFieldComplete = false;
	}
};

} /* namespace detail */


class ParseError: public std::runtime_error
{
public:
	ParseError(const std::string& msg): std::runtime_error(msg) {}
};

template <typename IterT>
struct IsContiguousMemoryForwardIterator: std::is_pointer<IterT> {};

template <>
struct IsContiguousMemoryForwardIterator
		<typename std::vector<char>::iterator>: std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::vector<char>::const_iterator>: std::true_type {};

#ifdef HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
#endif

struct Request
{
	using Type = enum http_method;
public:
	Type type = HTTP_HEAD;
	std::string url;
	std::string body;
	Headers headers;
public:
	Request() = default;
	Request(const Request&) = default;
	Request(Request&&) = default;
	Request& operator=(const Request&) = default;
	Request& operator=(Request&&) = default;
};

class Parser
{
protected:
	http_parser p;
	std::size_t totalConsumedLength;

	Parser(http_parser_type parserType)
		: totalConsumedLength(0)
	{
		http_parser_init(&p, parserType);
		p.data = this;
	}

public:
	Parser(const Parser&) = delete;
	Parser& operator=(const Parser&) = delete;

	void feed(const char *input, std::size_t inputLength)
	{
		std::size_t consumedLength = http_parser_execute(
				&p, &detail::ParserSettings::get().s, input, inputLength);
		totalConsumedLength += consumedLength;
		if (consumedLength != inputLength) {
			std::ostringstream errMsg;
			errMsg << "HTTP Parse error on character "
					<< totalConsumedLength << " (character " << p.nread
					<< " in current request)";
			throw ParseError(errMsg.str().c_str());
		}
	}

	template<typename IterT>
	typename std::enable_if<std::is_same<
			typename std::iterator_traits<IterT>::value_type, char>::value>::type
	feed(IterT begin, IterT end) { feedIter(begin, end); }

	void feedEof() { (void) feed(nullptr, 0); }

private:
	template<typename IterT>
	typename std::enable_if<!IsContiguousMemoryForwardIterator<IterT>::value>::type
	feedIter(IterT begin, IterT end)
	{
		for (IterT it = begin; it != end; ++it) {
			char c = *it;
			feed(&c, 1);
		}
	}
	template<typename IterT>
	typename std::enable_if<IsContiguousMemoryForwardIterator<IterT>::value>::type
	feedIter(IterT begin, IterT end)
	{
		const char *buf = &(*begin);
		const std::size_t len = end - begin;
		feed(buf, len);
	}

private:
	friend struct detail::Callbacks;
	virtual int onMessageBegin() = 0;
	virtual int onUrl(const char *data, std::size_t length) = 0;
	virtual int onStatus(const char *data, std::size_t length) = 0;
	virtual int onHeaderField(const char *data, std::size_t length) = 0;
	virtual int onHeaderValue(const char *data, std::size_t length) = 0;
	virtual int onHeadersComplete() = 0;
	virtual int onBody(const char *data, std::size_t length) = 0;
	virtual int onMessageComplete() = 0;
	virtual int onChunkHeader() = 0;
	virtual int onChunkComplete() = 0;
};

class RequestParser: public Parser
{
	RequestConsumer requestConsumer;
	Request currentRequest;
	detail::HeaderAssembler headerAssembler;

public:
	std::deque<Request> parsedRequests;
public:
	RequestParser()
		: Parser(HTTP_REQUEST), headerAssembler(currentRequest.headers) {}
	RequestParser(RequestConsumer requestConsumer)
		: Parser(HTTP_REQUEST), requestConsumer(requestConsumer),
			headerAssembler(currentRequest.headers) {}

private:
	int onMessageBegin() override
	{
		//std::cout << __FUNCTION__ << std::endl;
		currentRequest = Request();
		headerAssembler.reset();
		return 0;
	}

	int onUrl(const char *data, std::size_t length) override
	{
		//std::cout << __FUNCTION__ << " (" << std::string(data, length) << ")" << std::endl;
		currentRequest.url.append(data, length);
		return 0;
	}

	int onStatus(const char *data, std::size_t length) override
	{
		//std::cout << __FUNCTION__ << " (" << std::string(data, length) << ")" << std::endl;
		assert(false); // not reached
		return 0;
	}

	int onHeaderField(const char *data, std::size_t length) override
	{
		//std::cout << __FUNCTION__ << " (" << std::string(data, length) << ")" << std::endl;
		headerAssembler.onHeaderField(data, length);
		return 0;
	}

	int onHeaderValue(const char *data, std::size_t length) override
	{
		// std::cout << __FUNCTION__ << " (" << std::string(data, length) << ")" << std::endl;
		headerAssembler.onHeaderValue(data, length);
		return 0;
	}

	int onHeadersComplete() override
	{
		// std::cout << __FUNCTION__ << std::endl;
		headerAssembler.onHeadersComplete();
		return 0;
	}

	int onBody(const char *data, std::size_t length) override
	{
		//std::cout << __FUNCTION__ << " (" << std::string(data, length) << ")" << std::endl;
		currentRequest.body.append(data, length);
		return 0;
	}

	int onMessageComplete() override
	{
		//std::cout << __FUNCTION__ << std::endl;
		currentRequest.type = static_cast<Request::Type>(p.method);
		if (requestConsumer) {
			requestConsumer(std::move(currentRequest));
		} else {
			parsedRequests.push_back(std::move(currentRequest));
		}
		return 0;
	}

	int onChunkHeader() override
	{
		// std::cout << __FUNCTION__ << " (" << p.content_length << ")" << std::endl;
		// TODO
		return 0;
	}

	int onChunkComplete() override
	{
		// std::cout << __FUNCTION__ << std::endl;
		// TODO
		return 0;
	}
};

namespace detail {

int Callbacks::onMessageBegin(http_parser* p)
		{ return ((Parser*) p->data)->onMessageBegin(); }
int Callbacks::onUrl(http_parser* p, const char *data, size_t length)
		{ return ((Parser*) p->data)->onUrl(data, length); }
int Callbacks::onStatus(http_parser* p, const char *data, size_t length)
		{ return ((Parser*) p->data)->onStatus(data, length); }
int Callbacks::onHeaderField(http_parser* p, const char *data, size_t length)
		{ return ((Parser*) p->data)->onHeaderField(data, length); }
int Callbacks::onHeaderValue(http_parser* p, const char *data, size_t length)
		{ return ((Parser*) p->data)->onHeaderValue(data, length); }
int Callbacks::onHeadersComplete(http_parser* p)
		{ return ((Parser*) p->data)->onHeadersComplete(); }
int Callbacks::onBody(http_parser* p, const char *data, size_t length)
		{ return ((Parser*) p->data)->onBody(data, length); }
int Callbacks::onMessageComplete(http_parser* p)
		{ return ((Parser*) p->data)->onMessageComplete(); }
int Callbacks::onChunkHeader(http_parser* p)
		{ return ((Parser*) p->data)->onChunkHeader(); }
int Callbacks::onChunkComplete(http_parser* p)
		{ return ((Parser*) p->data)->onChunkComplete(); }

} /* namespace detail */

} /* namespace http */

template<typename StreamT>
StreamT& operator<<(StreamT& stream, http::Request::Type reqType)
{
	stream << http_method_str(reqType);
	return stream;
}

template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::Request& req)
{
	stream << "HTTP " << req.type << " request\n"
			<< "\turl: '" << req.url << "'\n"
			<< "\theaders:\n";
	for (const auto& fvPair: req.headers) {
		stream << "\t\t'" << fvPair.first << "': '" << fvPair.second << "'\n";
	}
	stream << "\tbody is " << req.body.size() << " bytes long.";
	return stream;
}
