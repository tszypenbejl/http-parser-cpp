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
#include <cstdio> /* for snprintf */
#include <cassert>
#if defined(WIN32) || defined(WIN64) /* TODO: check if that actually helps*/
#include <cstring>
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif


namespace http {


using protocol_upgrade_handler =
		std::function<void(const char* begin, const char* end)>;


class parse_error : public std::runtime_error
{
public:
	using runtime_error::runtime_error;
};


class too_big_error : public std::runtime_error
{
public:
	using runtime_error::runtime_error;
};


class request_parse_error : public parse_error
{
public:
	using parse_error::parse_error;
};


class response_parse_error : public parse_error
{
public:
	using parse_error::parse_error;
};


class request_too_big : public too_big_error
{
public:
	using too_big_error::too_big_error;
};


class request_headers_too_big : public too_big_error
{
public:
	using too_big_error::too_big_error;
};


class response_too_big : public too_big_error
{
public:
	using too_big_error::too_big_error;
};


class response_headers_too_big : public too_big_error
{
public:
	using too_big_error::too_big_error;
};


class url_parse_error : public parse_error
{
public:
	using parse_error::parse_error;
};


class header_not_found_error : public std::runtime_error
{
public:
	using runtime_error::runtime_error;
};


namespace detail {


template<typename Parser>
class callbacks
{
	template<typename MethodT, typename... ArgsT>
	inline static int call(http_parser* p, MethodT method, ArgsT... args)
	{
		Parser& parser = *((Parser*) p->data);
		try {
			return (parser.*method)(args...);
		} catch (...) {
			parser.callback_exception_ = std::current_exception();
		}
		return -1;
		
	}

public:
	static int on_message_begin(http_parser* p) noexcept
			{ return call(p, &Parser::on_message_begin); }

	static int on_url(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::on_url, data, length); }

	static int on_status(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::on_status, data, length); }

	static int on_header_field(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::on_header_field, data, length); }

	static int on_header_value(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::on_header_value, data, length); }

	static int on_headers_complete(http_parser* p) noexcept
			{ return call(p, &Parser::on_headers_complete); }

	static int on_message_complete(http_parser* p) noexcept
			{ return call(p, &Parser::on_message_complete); }

	static int on_body(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::on_body, data, length); }

	static int on_chunk_header(http_parser* p) noexcept
			{ return call(p, &Parser::on_chunk_header); }

	static int on_chunk_complete(http_parser* p) noexcept
			{ return call(p, &Parser::on_chunk_complete); }
};


template<typename Parser>
class parser_settings
{
	http_parser_settings s_;

public:
	static http_parser_settings& get()
	{
		static parser_settings instance;
		return instance.s_;
	}

	parser_settings(const parser_settings&) = delete;
	parser_settings(parser_settings&&)      = delete;

private:
	parser_settings()
	{
		http_parser_settings_init(&s_);
		s_.on_message_begin    = &callbacks<Parser>::on_message_begin;
		s_.on_url              = &callbacks<Parser>::on_url;
		s_.on_status           = &callbacks<Parser>::on_status;
		s_.on_header_field     = &callbacks<Parser>::on_header_field;
		s_.on_header_value     = &callbacks<Parser>::on_header_value;
		s_.on_headers_complete = &callbacks<Parser>::on_headers_complete;
		s_.on_body             = &callbacks<Parser>::on_body;
		s_.on_message_complete = &callbacks<Parser>::on_message_complete;
		s_.on_chunk_header     = &callbacks<Parser>::on_chunk_header;
		s_.on_chunk_complete   = &callbacks<Parser>::on_chunk_complete;
	}
};


struct header_name_less
{
	bool operator()	(const std::string& s1, const std::string& s2) const
			{ return strcasecmp(s1.c_str(), s2.c_str()) < 0; }
};


using headers = std::map<std::string, std::string, detail::header_name_less>;


class headers_owner
{
protected:
	headers headers_;

public:
	headers_owner()                                = default;
	headers_owner(const headers_owner&)            = default;
	headers_owner& operator=(const headers_owner&) = default;
	headers_owner(headers_owner&&)                 = default;
	headers_owner& operator=(headers_owner&&)      = default;

	void add_header(const std::string& name, const std::string& value)
	{
		std::string& current_value = headers_[name];
		if (current_value.empty()) {
			current_value = value;
		} else if (!value.empty()) {
			current_value.reserve(1 + value.size());
			current_value.append(",");
			current_value.append(value);
		}
	}

	bool has_header(const std::string& headerName) const noexcept
			{ return headers_.count(headerName) > 0U; }

	const std::string& get_header(const std::string& headerName) const
	{
		headers::const_iterator it = headers_.find(headerName);
		if (headers_.cend() == it) {
			throw header_not_found_error(
					"Request does not have '" + headerName + "' header");
		}
		return it->second;
	}

	const std::string& get_header(const std::string& headerName,
			const std::string& defaultValue) const noexcept
	{
		headers::const_iterator it = headers_.find(headerName);
		return headers_.cend() == it ? defaultValue : it->second;
	}

	std::size_t header_count() const noexcept { return headers_.size(); }

	const headers& all_headers() const noexcept { return headers_; }
};


class headers_assembler
{
	headers_owner& headers_;
	std::string    current_header_field_;
	std::string    current_header_value_;
	bool           current_header_field_complete_ = false;

public:
	headers_assembler(headers_owner& h): headers_(h) {}
	headers_assembler(const headers_assembler&)            = delete;
	headers_assembler(headers_assembler&&)                 = delete;
	headers_assembler& operator=(const headers_assembler&) = delete;
	headers_assembler& operator=(headers_assembler&&)      = delete;

	void reset()
	{
		current_header_field_.clear();
		current_header_value_.clear();
		current_header_field_complete_ = false;
	}

	void on_header_field(const char* data, std::size_t length)
	{
		if (current_header_field_complete_) {
			on_single_header_complete();
		}
		current_header_field_.append(data, length);
	}

	void on_header_value(const char* data, std::size_t length)
	{
		current_header_value_.append(data, length);
		current_header_field_complete_ = true;
	}

	void on_headers_complete()
	{
		on_single_header_complete();
	}

private:
	void on_single_header_complete()
	{
		if (current_header_field_.empty()) {
			return;
		}
		headers_.add_header(current_header_field_, current_header_value_);
		current_header_field_.clear();
		current_header_value_.clear();
		current_header_field_complete_ = false;
	}
};


class length_limiter
{
public:
	using on_limit_exceeded =
			std::function<void(std::size_t, std::size_t)>;

private:
	std::size_t       current_length_    = 0;
	std::size_t       max_length_        = 0;
	on_limit_exceeded on_limit_exceeded_;

public:
	length_limiter(on_limit_exceeded on_limit_exceeded):
			on_limit_exceeded_(on_limit_exceeded) {}

	inline std::size_t max_length() const noexcept { return max_length_; }

	inline void max_length(std::size_t max) { max_length_ = max; }

	inline void check_length(std::size_t delta)
	{
		current_length_ += delta;
		if (max_length_ && current_length_ > max_length_) {
			on_limit_exceeded_(current_length_, max_length_);
		}
	}

	inline void reset() { current_length_ = 0; }
};


template <typename IterT>
struct is_contiguous_memory_forward_iterator : std::is_pointer<IterT> {};

template <>
struct is_contiguous_memory_forward_iterator
		<typename std::vector<char>::iterator> : std::true_type {};
template <>
struct is_contiguous_memory_forward_iterator
		<typename std::vector<char>::const_iterator> : std::true_type {};
template <>
struct is_contiguous_memory_forward_iterator
		<typename std::string::iterator> : std::true_type {};
template <>
struct is_contiguous_memory_forward_iterator
		<typename std::string::const_iterator> : std::true_type {};

#ifdef HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
#endif


class parser_base
{
protected:
	http_parser              p_;
	http_parser_settings&    parser_settings_;
	std::exception_ptr       callback_exception_;
	std::size_t              total_consumed_length_    = 0;
	protocol_upgrade_handler protocol_upgrade_handler_;
	std::string              protocol_upgrade_data_;

protected:
	parser_base(http_parser_type parser_type, http_parser_settings& parser_settings)
		: parser_settings_(parser_settings)
	{
		http_parser_init(&p_, parser_type);
		p_.data = this;
	}

	virtual void throw_parse_error(const std::string& errorMessage) = 0;

public:
	parser_base(const parser_base&) = delete;
	parser_base& operator=(const parser_base&) = delete;

	inline const std::string& protocol_upgrade_data() const noexcept
			{ return protocol_upgrade_data_; }
	inline std::string pop_protocol_upgrade_data()
			{ return std::move(protocol_upgrade_data_); }

	virtual ~parser_base() {}

	void feed(const char* input, std::size_t input_length)
	{
		if (p_.upgrade) {
			if (protocol_upgrade_handler_) {
				protocol_upgrade_handler_(input, input + input_length);
			} else {
				protocol_upgrade_data_.append(input, input_length);
			}
		} else {
			std::size_t consumed_length = http_parser_execute(
					&p_, &parser_settings_, input, input_length);
			total_consumed_length_ += consumed_length;
			if (callback_exception_) {
				std::exception_ptr e = nullptr;
				std::swap(e, callback_exception_);
				std::rethrow_exception(e);
			}
			if (HTTP_PARSER_ERRNO(&p_) != HPE_OK || consumed_length > input_length
					|| (consumed_length < input_length && !p_.upgrade)) {
				std::ostringstream errMsg;
				errMsg << "HTTP Parse error on character " << total_consumed_length_
						<< ": " << http_errno_name(HTTP_PARSER_ERRNO(&p_));
				throw_parse_error(errMsg.str());
			}
			if (p_.upgrade) {
				feed(input + consumed_length, input_length - consumed_length);
			}
		}
	}

	template<typename IterT>
	typename std::enable_if<std::is_same<
			typename std::iterator_traits<IterT>::value_type, char>::value>::type
	feed(IterT begin, IterT end) { feed_iter(begin, end); }

	void feed_eof() { (void) feed(nullptr, 0); }

private:
	template<typename IterT>
	typename std::enable_if<!is_contiguous_memory_forward_iterator<IterT>::value>::type
	feed_iter(IterT begin, IterT end)
	{
		for (IterT it = begin; it != end; ++it) {
			char c = *it;
			feed(&c, 1);
		}
	}

	template<typename IterT>
	typename std::enable_if<is_contiguous_memory_forward_iterator<IterT>::value>::type
	feed_iter(IterT begin, IterT end)
	{
		const char* buf = &(*begin);
		const std::size_t len = end - begin;
		feed(buf, len);
	}
};


} /* namespace detail */


class http_version_t
{
	unsigned short major_ = 0;
	unsigned short minor_ = 0;

public:
	http_version_t(unsigned short major, unsigned short minor) : major_(major), minor_(minor) {}
	http_version_t() = default;
	http_version_t(const http_version_t&)            = default;
	http_version_t(http_version_t&&)                 = default;
	http_version_t& operator=(const http_version_t&) = default;
	http_version_t& operator=(http_version_t&&)      = default;

	bool operator==(const http_version_t& other) const noexcept
			{ return other.major_ == major_ && other.minor_ == minor_; }

	inline unsigned short major() const noexcept { return major_; }
	inline void major(unsigned short m) noexcept { major_ = m; }

	inline unsigned short minor() const noexcept { return minor_; }
	inline void minor(unsigned short m) noexcept { minor_ = m; }

	std::string to_string() const
	{
		std::string ret;
		ret.reserve(3);
		char buf[12];
		(void) std::snprintf(buf, sizeof(buf), "%u", major_);
		ret.append(buf);
		ret.append(".");
		(void) std::snprintf(buf, sizeof(buf), "%u", minor_);
		ret.append(buf);
		return ret;
	}
};


class request_head : public detail::headers_owner
{
public:
	using method_t = enum http_method;

private:
	method_t       method_       = HTTP_HEAD;
	http_version_t http_version_;
	bool           keep_alive_   = false;
	std::string    url_;

public:
	request_head()                               = default;
	request_head(const request_head&)            = default;
	request_head(request_head&&)                 = default;
	request_head& operator=(const request_head&) = default;
	request_head& operator=(request_head&&)      = default;

	inline method_t           method()       const noexcept { return method_; }
	inline http_version_t     http_version() const noexcept { return http_version_; }
	inline bool               keep_alive()   const noexcept { return keep_alive_; }
	inline const std::string& url()          const noexcept { return url_; }

	inline void method(method_t m)             noexcept { method_ = m; }
	inline void http_versIon(http_version_t v) noexcept { http_version_ = v; }
	inline void keep_alive(bool ka)            noexcept { keep_alive_ = ka; }
	inline void url(std::string u)                      { url_ = std::move(u); }

	inline void append_url(const char *d, std::size_t len) { url_.append(d, len); }
};


class request : public request_head
{
	std::string body_;

public:
	request()                          = default;
	request(const request&)            = default;
	request(request&&)                 = default;
	request& operator=(const request&) = default;
	request& operator=(request&&)      = default;

	inline const request_head& head() const noexcept { return *this; }
	inline const std::string&  body() const noexcept { return body_; }

	inline void head(request_head h) { *static_cast<request_head*>(this) = std::move(h); }
	inline void body(std::string b)  { body_ = std::move(b); }

	inline void append_body(const char* d, std::size_t len) { body_.append(d, len); }
};


struct ResponseHead : detail::headers_owner
{
	unsigned statusCode = 0;
	std::string statusText;
	http_version_t http_version_;
	bool keepAlive = false;
public:
	ResponseHead()                               = default;
	ResponseHead(const ResponseHead&)            = default;
	ResponseHead(ResponseHead&&)                 = default;
	ResponseHead& operator=(const ResponseHead&) = default;
	ResponseHead& operator=(ResponseHead&&)      = default;
};

struct Response : ResponseHead
{
	std::string body;
public:
	const ResponseHead& head() const noexcept { return *this; }
	void head(ResponseHead h) { *static_cast<ResponseHead*>(this) = std::move(h); }
};

using RequestConsumer = std::function<void(request&&)>;
using ResponseConsumer = std::function<void(Response&&)>;

class RequestParser : public detail::parser_base
{
	request currentRequest;
	detail::headers_assembler header_assembler_ { currentRequest };
	RequestConsumer requestConsumer;
	detail::length_limiter requestLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw request_too_big("Request exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	std::deque<request> parsedRequests;

public:
	RequestParser()
		: parser_base(HTTP_REQUEST, detail::parser_settings<RequestParser>::get()) {}

	RequestParser(RequestConsumer requestConsumer)
		: parser_base(HTTP_REQUEST, detail::parser_settings<RequestParser>::get()),
			requestConsumer(requestConsumer) {}

	RequestParser(protocol_upgrade_handler protocolUpgradeHandler)
		: parser_base(HTTP_REQUEST, detail::parser_settings<RequestParser>::get())
	{
		this->protocol_upgrade_handler_ = protocolUpgradeHandler;
	}

	RequestParser(RequestConsumer requestConsumer,
			protocol_upgrade_handler protocolUpgradeHandler)
		: parser_base(HTTP_REQUEST, detail::parser_settings<RequestParser>::get()),
			requestConsumer(requestConsumer)
	{
		this->protocol_upgrade_handler_ = protocolUpgradeHandler;
	}

	void setMaxRequestLength(std::size_t maxLength) // 0 means unlimited
			{ requestLengthLimiter.max_length(maxLength); }

private:
	void throw_parse_error(const std::string& errorMessage) override
			{ throw request_parse_error(errorMessage); }

private:
	friend struct detail::callbacks<RequestParser>;

	int on_message_begin()
	{
		currentRequest = request();
		header_assembler_.reset();
		requestLengthLimiter.reset();
		return 0;
	}

	int on_url(const char* data, std::size_t length)
	{
		requestLengthLimiter.check_length(length);
		currentRequest.append_url(data, length);
		return 0;
	}

	int on_status(const char* data, std::size_t length)
	{
		assert(false); // not reached
		return 0;
	}

	int on_header_field(const char* data, std::size_t length)
	{
		requestLengthLimiter.check_length(length);
		header_assembler_.on_header_field(data, length);
		return 0;
	}

	int on_header_value(const char* data, std::size_t length)
	{
		requestLengthLimiter.check_length(length);
		header_assembler_.on_header_value(data, length);
		return 0;
	}

	int on_headers_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}

	int on_body(const char* data, std::size_t length)
	{
		requestLengthLimiter.check_length(length);
		currentRequest.append_body(data, length);
		return 0;
	}

	int on_message_complete()
	{
		currentRequest.method(static_cast<request_head::method_t>(p_.method));
		currentRequest.http_versIon(http_version_t(p_.http_major, p_.http_minor));
		currentRequest.keep_alive(http_should_keep_alive(&p_) != 0);
		if (requestConsumer) {
			requestConsumer(std::move(currentRequest));
		} else {
			parsedRequests.push_back(std::move(currentRequest));
		}
		return 0;
	}

	int on_chunk_header()
	{
		header_assembler_.reset();
		return 0;
	}

	int on_chunk_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}
};

class ResponseParser : public detail::parser_base
{
	Response currentResponse;
	detail::headers_assembler header_assembler_ { currentResponse };
	ResponseConsumer responseConsumer;
	detail::length_limiter responseLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw response_too_big("Response exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	std::deque<Response> parsedResponses;

public:
	ResponseParser()
		: parser_base(HTTP_RESPONSE, detail::parser_settings<ResponseParser>::get()) {}

	ResponseParser(ResponseConsumer responseConsumer)
		: parser_base(HTTP_RESPONSE, detail::parser_settings<ResponseParser>::get()),
			responseConsumer(responseConsumer) {}

	ResponseParser(protocol_upgrade_handler protocolUpgradeHandler)
		: parser_base(HTTP_RESPONSE, detail::parser_settings<ResponseParser>::get())
	{
		this->protocol_upgrade_handler_ = protocolUpgradeHandler;
	}

	ResponseParser(ResponseConsumer responseConsumer,
			protocol_upgrade_handler protocolUpgradeHandler)
		: parser_base(HTTP_RESPONSE, detail::parser_settings<ResponseParser>::get()),
			responseConsumer(responseConsumer)
	{
		this->protocol_upgrade_handler_ = protocolUpgradeHandler;
	}

	void setMaxResponseLength(std::size_t maxLength) // 0 means unlimited
			{ responseLengthLimiter.max_length(maxLength); }

private:
	void throw_parse_error(const std::string& errorMessage) override
			{ throw response_parse_error(errorMessage); }

private:
	friend struct detail::callbacks<ResponseParser>;

	int on_message_begin()
	{
		currentResponse = Response();
		header_assembler_.reset();
		responseLengthLimiter.reset();
		return 0;
	}

	int on_url(const char* data, std::size_t length)
	{
		(void) data;
		(void) length;
		assert(false); // not reached
		return 0;
	}

	int on_status(const char* data, std::size_t length)
	{
		currentResponse.statusText.append(data, length);
		return 0;
	}

	int on_header_field(const char* data, std::size_t length)
	{
		responseLengthLimiter.check_length(length);
		header_assembler_.on_header_field(data, length);
		return 0;
	}

	int on_header_value(const char* data, std::size_t length)
	{
		responseLengthLimiter.check_length(length);
		header_assembler_.on_header_value(data, length);
		return 0;
	}

	int on_headers_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}

	int on_body(const char* data, std::size_t length)
	{
		responseLengthLimiter.check_length(length);
		currentResponse.body.append(data, length);
		return 0;
	}

	int on_message_complete()
	{
		currentResponse.statusCode = p_.status_code;
		currentResponse.http_version_.major(p_.http_major);
		currentResponse.http_version_.minor(p_.http_minor);
		currentResponse.keepAlive = (http_should_keep_alive(&p_) != 0);
		if (responseConsumer) {
			responseConsumer(std::move(currentResponse));
		} else {
			parsedResponses.push_back(std::move(currentResponse));
		}
		return 0;
	}

	int on_chunk_header()
	{
		header_assembler_.reset();
		return 0;
	}

	int on_chunk_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}
};

using BigRequestCallback = std::function<void(const request_head &requestHead,
		const char *bodyPart, std::size_t bodyPartLength, bool finished)>;

class BigRequestParser : public detail::parser_base
{
	request_head currentRequest;
	detail::headers_assembler header_assembler_ { currentRequest };
	BigRequestCallback requestCallback;
	detail::length_limiter headersLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw request_headers_too_big("Request headers exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	BigRequestParser(BigRequestCallback requestCallback,
			protocol_upgrade_handler protocolUpgradeHandler = nullptr)
		: parser_base(HTTP_REQUEST, detail::parser_settings<BigRequestParser>::get()),
			requestCallback(requestCallback)
	{
		this->protocol_upgrade_handler_ = protocolUpgradeHandler;
	}

	void setMaxHeadersLength(std::size_t maxLength) // 0 means unlimited
			{ headersLengthLimiter.max_length(maxLength); }

private:
	void throw_parse_error(const std::string& errorMessage) override
			{ throw request_parse_error(errorMessage); }

private:
	friend struct detail::callbacks<BigRequestParser>;

	int on_message_begin()
	{
		currentRequest = request_head();
		header_assembler_.reset();
		headersLengthLimiter.reset();
		return 0;
	}

	int on_url(const char* data, std::size_t length)
	{
		headersLengthLimiter.check_length(length);
		currentRequest.append_url(data, length);
		return 0;
	}

	int on_status(const char* data, std::size_t length)
	{
		assert(false); // not reached
		return 0;
	}

	int on_header_field(const char* data, std::size_t length)
	{
		headersLengthLimiter.check_length(length);
		header_assembler_.on_header_field(data, length);
		return 0;
	}

	int on_header_value(const char* data, std::size_t length)
	{
		headersLengthLimiter.check_length(length);
		header_assembler_.on_header_value(data, length);
		return 0;
	}

	int on_headers_complete()
	{
		header_assembler_.on_headers_complete();
		currentRequest.method(static_cast<request_head::method_t>(p_.method));
		currentRequest.http_versIon(http_version_t(p_.http_major, p_.http_minor));
		currentRequest.keep_alive(http_should_keep_alive(&p_) != 0);
		return 0;
	}

	int on_body(const char* data, std::size_t length)
	{
		requestCallback(currentRequest, data, length, false);
		return 0;
	}

	int on_message_complete()
	{
		requestCallback(currentRequest, nullptr, 0, true);
		return 0;
	}

	int on_chunk_header()
	{
		header_assembler_.reset();
		return 0;
	}

	int on_chunk_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}
};

using BigResponseCallback = std::function<void(const ResponseHead &responseHead,
		const char *bodyPart, std::size_t bodyPartLength, bool finished)>;

class BigResponseParser : public detail::parser_base
{
	ResponseHead currentResponse;
	detail::headers_assembler header_assembler_ { currentResponse };
	BigResponseCallback responseCallback;
	detail::length_limiter headersLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw response_headers_too_big("Response headers exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	BigResponseParser(BigResponseCallback responseCallback,
			protocol_upgrade_handler protocolUpgradeHandler = nullptr)
		: parser_base(HTTP_RESPONSE,
					detail::parser_settings<BigResponseParser>::get()),
			responseCallback(responseCallback)
	{
		this->protocol_upgrade_handler_ = protocolUpgradeHandler;
	}

	void setMaxHeadersLength(std::size_t maxLength) // 0 means unlimited
			{ headersLengthLimiter.max_length(maxLength); }

private:
	void throw_parse_error(const std::string& errorMessage) override
			{ throw response_parse_error(errorMessage); }

private:
	friend struct detail::callbacks<BigResponseParser>;

	int on_message_begin()
	{
		currentResponse = ResponseHead();
		header_assembler_.reset();
		headersLengthLimiter.reset();
		return 0;
	}

	int on_url(const char* data, std::size_t length)
	{
		(void) data;
		(void) length;
		assert(false); // not reached
		return 0;
	}

	int on_status(const char* data, std::size_t length)
	{
		headersLengthLimiter.check_length(length);
		currentResponse.statusText.append(data, length);
		return 0;
	}

	int on_header_field(const char* data, std::size_t length)
	{
		headersLengthLimiter.check_length(length);
		header_assembler_.on_header_field(data, length);
		return 0;
	}

	int on_header_value(const char* data, std::size_t length)
	{
		headersLengthLimiter.check_length(length);
		header_assembler_.on_header_value(data, length);
		return 0;
	}

	int on_headers_complete()
	{
		header_assembler_.on_headers_complete();
		currentResponse.statusCode = p_.status_code;
		currentResponse.http_version_.major(p_.http_major);
		currentResponse.http_version_.minor(p_.http_minor);
		currentResponse.keepAlive = (http_should_keep_alive(&p_) != 0);
		return 0;
	}

	int on_body(const char* data, std::size_t length)
	{
		responseCallback(currentResponse, data, length, false);
		return 0;
	}

	int on_message_complete()
	{
		responseCallback(currentResponse, nullptr, 0, true);
		return 0;
	}

	int on_chunk_header()
	{
		header_assembler_.reset();
		return 0;
	}

	int on_chunk_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}
};


struct Url
{
	std::string schema;
	std::string host;
	std::string path;
	std::string query;
	std::string fragment;
	std::string userinfo;
	unsigned    port     = 0;
};


Url parse_url(const std::string& input, bool is_connect = false)
{
	http_parser_url u;
	http_parser_url_init(&u);
	int err = http_parser_parse_url(
			input.c_str(), input.size(), int(is_connect), &u);
	if (err) {
		throw url_parse_error("Failed to parse this url: '" + input + "'");
	}

	Url parsed_url;

	using field_t = std::pair<http_parser_url_fields, std::string Url::*>;
	static const field_t string_fields[] = {
		{ UF_SCHEMA, &Url::schema },
		{ UF_HOST, &Url::host },
		{ UF_PATH, &Url::path },
		{ UF_QUERY, &Url::query },
		{ UF_FRAGMENT, &Url::fragment },
		{ UF_USERINFO, &Url::userinfo }
	};
	for (const field_t& field : string_fields) {
		if (u.field_set & (1 << field.first)) {
			parsed_url.*field.second = input.substr(
					u.field_data[field.first].off, u.field_data[field.first].len);
		}
	}

	if (u.field_set & (1 << UF_PORT)) {
		parsed_url.port = std::stoul(input.substr(
				u.field_data[UF_PORT].off, u.field_data[UF_PORT].len
		));
	}

	return parsed_url;
}


using detail::headers;


} /* namespace http */


template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::http_version_t& ver)
{
	stream << ver.to_string();
	return stream;
}

template<typename StreamT>
StreamT& operator<<(StreamT& stream, http::request_head::method_t method)
{
	stream << http_method_str(method);
	return stream;
}

template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::request& req)
{
	stream << "HTTP/" << req.http_version_ << " " << req.method_ << " request.\n"
			<< "\tUrl: '" << req.url_ << "'\n"
			<< "\tHeaders:\n";
	for (const auto& fvPair : req.headers_) {
		stream << "\t\t'" << fvPair.first << "': '" << fvPair.second << "'\n";
	}
	stream << "\tBody is " << req.body().size() << " bytes long.\n\tKeepAlive: "
			<< (req.keep_alive_ ? "yes" : "no") << ".";
	return stream;
}

template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::Response& resp)
{
	stream << "HTTP/" << resp.http_version_ << " '" << resp.statusCode << "' "
			<< resp.statusText << " response.\n"
			<< "\tHeaders:\n";
	for (const auto& fvPair : resp.headers_) {
		stream << "\t\t'" << fvPair.first << "': '" << fvPair.second << "'\n";
	}
	stream << "\tBody is " << resp.body.size() << " bytes long.\n\tKeepAlive: "
			<< (resp.keepAlive ? "yes" : "no") << ".";
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
