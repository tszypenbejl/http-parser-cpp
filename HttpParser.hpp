#pragma once

#include <http_parser.h>
#include <stdexcept>
#include <string>
#include <vector>
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

template<typename ParserT>
struct Callbacks
{
	static int onMessageBegin(http_parser* p)
			{ return ((ParserT*) p->data)->onMessageBegin(); }
	static int onUrl(http_parser* p, const char* data, size_t length)
			{ return ((ParserT*) p->data)->onUrl(data, length); }
	static int onStatus(http_parser* p, const char* data, size_t length)
			{ return ((ParserT*) p->data)->onStatus(data, length); }
	static int onHeaderField(http_parser* p, const char* data, size_t length)
			{ return ((ParserT*) p->data)->onHeaderField(data, length); }
	static int onHeaderValue(http_parser* p, const char* data, size_t length)
			{ return ((ParserT*) p->data)->onHeaderValue(data, length); }
	static int onHeadersComplete(http_parser* p)
			{ return ((ParserT*) p->data)->onHeadersComplete(); }
	static int onMessageComplete(http_parser* p)
			{ return ((ParserT*) p->data)->onMessageComplete(); }
	static int onBody(http_parser* p, const char* data, size_t length)
			{ return ((ParserT*) p->data)->onBody(data, length); }
	static int onChunkHeader(http_parser* p)
			{ return ((ParserT*) p->data)->onChunkHeader(); }
	static int onChunkComplete(http_parser* p)
			{ return ((ParserT*) p->data)->onChunkComplete(); }
};

template<typename ParserT>
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
		s.on_message_begin = &Callbacks<ParserT>::onMessageBegin;
		s.on_url = &Callbacks<ParserT>::onUrl;
		s.on_status = &Callbacks<ParserT>::onStatus;
		s.on_header_field = &Callbacks<ParserT>::onHeaderField;
		s.on_header_value = &Callbacks<ParserT>::onHeaderValue;
		s.on_headers_complete = &Callbacks<ParserT>::onHeadersComplete;
		s.on_body = &Callbacks<ParserT>::onBody;
		s.on_message_complete = &Callbacks<ParserT>::onMessageComplete;
		s.on_chunk_header = &Callbacks<ParserT>::onChunkHeader;
		s.on_chunk_complete = &Callbacks<ParserT>::onChunkComplete;
	}
};

class HeaderAssembler
{
	Headers& headers;
	std::string currentHeaderField;
	std::string currentHeaderValue;
	bool currentHeaderFieldComplete = false;

public:
	HeaderAssembler(Headers& headers): headers(headers) {}
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

	void onHeaderField(const char* data, std::size_t length)
	{
		if (currentHeaderFieldComplete) {
			onSingleHeaderComplete();
		}
		currentHeaderField.append(data, length);
	}

	void onHeaderValue(const char* data, std::size_t length)
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

class RequestParseError: public ParseError
{
public:
	RequestParseError(const std::string& msg): ParseError(msg) {}
};

class UrlParseError: public ParseError
{
public:
	UrlParseError(const std::string& msg): ParseError(msg) {}
};

template <typename IterT>
struct IsContiguousMemoryForwardIterator: std::is_pointer<IterT> {};

template <>
struct IsContiguousMemoryForwardIterator
		<typename std::vector<char>::iterator>: std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::vector<char>::const_iterator>: std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::string::iterator>: std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::string::const_iterator>: std::true_type {};

#ifdef HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
#endif

struct Url
{
	std::string schema;
	std::string host;
	std::string path;
	std::string query;
	std::string fragment;
	std::string userinfo;
	unsigned port = 0;
};

Url parseUrl(const std::string& input, bool isConnect = false)
{
	http_parser_url u;
	http_parser_url_init(&u);
	int err = http_parser_parse_url(
			input.c_str(), input.size(), int(isConnect), &u);
	if (err) {
		throw UrlParseError("Failed to parse this url: '" + input + "'");
	}

	Url parsedUrl;

	using FieldDef = std::pair<http_parser_url_fields, std::string Url::*>;
	static const FieldDef stringFields[] = {
		{ UF_SCHEMA, &Url::schema },
		{ UF_HOST, &Url::host },
		{ UF_PATH, &Url::path },
		{ UF_QUERY, &Url::query },
		{ UF_FRAGMENT, &Url::fragment },
		{ UF_USERINFO, &Url::userinfo }
	};
	for (const FieldDef& field: stringFields) {
		if (u.field_set & (1 << field.first)) {
			parsedUrl.*field.second = input.substr(
					u.field_data[field.first].off, u.field_data[field.first].len);
		}
	}

	if (u.field_set & (1 << UF_PORT)) {
		parsedUrl.port = std::stoul(input.substr(
				u.field_data[UF_PORT].off, u.field_data[UF_PORT].len
		));
	}

	return parsedUrl;
}

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
	http_parser_settings& parserSettings;
	std::size_t totalConsumedLength;

	Parser(http_parser_type parserType, http_parser_settings& parserSettings)
		: parserSettings(parserSettings), totalConsumedLength(0)
	{
		http_parser_init(&p, parserType);
		p.data = this;
	}

	virtual ~Parser() {}

public:
	Parser(const Parser&) = delete;
	Parser& operator=(const Parser&) = delete;

	void feed(const char* input, std::size_t inputLength)
	{
		std::size_t consumedLength = http_parser_execute(
				&p, &parserSettings, input, inputLength);
		totalConsumedLength += consumedLength;
		if (consumedLength != inputLength || HTTP_PARSER_ERRNO(&p) != HPE_OK) {
			std::ostringstream errMsg;
			errMsg << "HTTP Parse error on character "
					<< totalConsumedLength << " (character " << p.nread
					<< " in current request): " << http_errno_name(HTTP_PARSER_ERRNO(&p));
			throw RequestParseError(errMsg.str().c_str());
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
};

class RequestParser: public Parser
{
	Request currentRequest;
	detail::HeaderAssembler headerAssembler;
	RequestConsumer requestConsumer;

public:
	std::deque<Request> parsedRequests;

public:
	RequestParser()
		: Parser(HTTP_REQUEST, detail::ParserSettings<RequestParser>::get().s),
			headerAssembler(currentRequest.headers) {}

	RequestParser(RequestConsumer requestConsumer)
		: Parser(HTTP_REQUEST, detail::ParserSettings<RequestParser>::get().s),
			headerAssembler(currentRequest.headers), requestConsumer(requestConsumer) {}

private:
	friend struct detail::Callbacks<RequestParser>;

	int onMessageBegin()
	{
		currentRequest = Request();
		headerAssembler.reset();
		return 0;
	}

	int onUrl(const char* data, std::size_t length)
	{
		currentRequest.url.append(data, length);
		return 0;
	}

	int onStatus(const char* data, std::size_t length)
	{
		assert(false); // not reached
		return 0;
	}

	int onHeaderField(const char* data, std::size_t length)
	{
		headerAssembler.onHeaderField(data, length);
		return 0;
	}

	int onHeaderValue(const char* data, std::size_t length)
	{
		headerAssembler.onHeaderValue(data, length);
		return 0;
	}

	int onHeadersComplete()
	{
		headerAssembler.onHeadersComplete();
		return 0;
	}

	int onBody(const char* data, std::size_t length)
	{
		currentRequest.body.append(data, length);
		return 0;
	}

	int onMessageComplete()
	{
		currentRequest.type = static_cast<Request::Type>(p.method);
		if (requestConsumer) {
			requestConsumer(std::move(currentRequest));
		} else {
			parsedRequests.push_back(std::move(currentRequest));
		}
		return 0;
	}

	int onChunkHeader()
	{
		// std::cout << __FUNCTION__ << " (" << p.content_length << ")" << std::endl;
		// TODO
		return 0;
	}

	int onChunkComplete()
	{
		// std::cout << __FUNCTION__ << std::endl;
		// TODO
		return 0;
	}
};

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

template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::Url& url)
{
	stream << "URL\n"
			<< "schema: '" << url.schema << "'\n"
			<< "host: '" << url.host << "'\n"
			<< "port: " << url.port << "\n"
			<< "path: '" << url.path << "'\n"
			<< "query: '" << url.query << "'\n"
			<< "fragment: '" << url.fragment << "'\n"
			<< "userinfo: '" << url.userinfo << "'\n";
	return stream;
}
