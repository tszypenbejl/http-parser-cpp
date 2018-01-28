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


using protocol_upgrade_handler =
        std::function<void(const char* begin, const char* end)>;


namespace detail {


template<typename Parser>
class callbacks
{
    template<typename Method, typename... Args>
    inline static int call(http_parser* p, Method method, Args... args)
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
    bool operator()    (const std::string& s1, const std::string& s2) const
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

    bool has_header(const std::string& header_name) const noexcept
            { return headers_.count(header_name) > 0U; }

    const std::string& get_header(const std::string& header_name) const
    {
        headers::const_iterator it = headers_.find(header_name);
        if (headers_.cend() == it) {
            throw header_not_found_error(
                    "Request does not have '" + header_name + "' header");
        }
        return it->second;
    }

    const std::string& get_header(const std::string& header_name,
            const std::string& default_value) const noexcept
    {
        headers::const_iterator it = headers_.find(header_name);
        return headers_.cend() == it ? default_value : it->second;
    }

    std::size_t header_count() const noexcept { return headers_.size(); }

    const headers& all_headers() const noexcept { return headers_; }
};


class body_owner
{
    std::string body_;

public:
    body_owner()                             = default;
    body_owner(const body_owner&)            = default;
    body_owner& operator=(const body_owner&) = default;
    body_owner(body_owner&&)                 = default;
    body_owner& operator=(body_owner&&)      = default;

    inline const std::string& body() const noexcept { return body_; }
    inline void body(std::string b) { body_ = std::move(b); }
    inline void append_body(const char* d, std::size_t len) { body_.append(d, len); }
    inline std::string pop_body() { return std::move(body_); }
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


template <typename Iter>
struct is_contiguous_memory_forward_iterator : std::is_pointer<Iter> {};

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

    virtual void throw_parse_error(const std::string& error_message) = 0;

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
                std::ostringstream err_msg;
                err_msg << "HTTP Parse error on character " << total_consumed_length_
                        << ": " << http_errno_name(HTTP_PARSER_ERRNO(&p_));
                throw_parse_error(err_msg.str());
            }
            if (p_.upgrade) {
                feed(input + consumed_length, input_length - consumed_length);
            }
        }
    }

    template<typename Iter>
    typename std::enable_if<std::is_same<
            typename std::iterator_traits<Iter>::value_type, char>::value>::type
    feed(Iter begin, Iter end) { feed_iter(begin, end); }

    void feed_eof() { (void) feed(nullptr, 0); }

private:
    template<typename Iter>
    typename std::enable_if<!is_contiguous_memory_forward_iterator<Iter>::value>::type
    feed_iter(Iter begin, Iter end)
    {
        for (Iter it = begin; it != end; ++it) {
            char c = *it;
            feed(&c, 1);
        }
    }

    template<typename Iter>
    typename std::enable_if<is_contiguous_memory_forward_iterator<Iter>::value>::type
    feed_iter(Iter begin, Iter end)
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
    inline void http_version(http_version_t v) noexcept { http_version_ = v; }
    inline void keep_alive(bool ka)            noexcept { keep_alive_ = ka; }
    inline void url(std::string u)                      { url_ = std::move(u); }

    inline void append_url(const char *d, std::size_t len) { url_.append(d, len); }
};


class request : public request_head, public detail::body_owner
{
public:
    request()                          = default;
    request(const request&)            = default;
    request(request&&)                 = default;
    request& operator=(const request&) = default;
    request& operator=(request&&)      = default;

    inline const request_head& head() const noexcept { return *this; }
    inline void head(request_head h) { *static_cast<request_head*>(this) = std::move(h); }
};


class response_head : public detail::headers_owner
{
    unsigned       status_code_  = 0;
    std::string    status_text_;
    http_version_t http_version_;
    bool           keep_alive_   = false;

public:
    response_head()                                = default;
    response_head(const response_head&)            = default;
    response_head(response_head&&)                 = default;
    response_head& operator=(const response_head&) = default;
    response_head& operator=(response_head&&)      = default;

    inline unsigned           status_code()  const noexcept { return status_code_; }
    inline const std::string& status_text()  const noexcept { return status_text_; }
    inline http_version_t     http_version() const noexcept { return http_version_; }
    inline bool               keep_alive()   const noexcept { return keep_alive_; }

    inline void status_code(unsigned sc)       noexcept { status_code_ = sc; }
    inline void status_text(std::string st) { status_text_ = std::move(st); }
    inline void http_version(http_version_t v) noexcept { http_version_ = v; }
    inline void keep_alive(bool ka)            noexcept { keep_alive_ = ka; }

    inline void append_status_text(const char *d, std::size_t len) { status_text_.append(d, len); }
};

class response : public response_head, public detail::body_owner
{
public:
    response()                           = default;
    response(const response&)            = default;
    response(response&&)                 = default;
    response& operator=(const response&) = default;
    response& operator=(response&&)      = default;

    const response_head& head() const noexcept { return *this; }
    void head(response_head h) { *static_cast<response_head*>(this) = std::move(h); }
};


class request_parser : public detail::parser_base
{
public:
    using new_request_callback = std::function<void(request_parser&)>;

private:
    request                   current_request_;
    detail::headers_assembler headers_assembler_      { current_request_ };
    new_request_callback      callback_;
    detail::length_limiter    request_length_limiter_ { [](std::size_t, std::size_t limit)
            {
                throw request_too_big("Request exceeded size limit of "
                        + std::to_string(limit));
            }};
    std::deque<request>       parsed_requests_;

public:
    request_parser()
        : parser_base(HTTP_REQUEST, detail::parser_settings<request_parser>::get()) {}

    request_parser(new_request_callback callback)
        : parser_base(HTTP_REQUEST, detail::parser_settings<request_parser>::get()),
            callback_(callback) {}

    request_parser(protocol_upgrade_handler protocol_upgrade_handler)
        : parser_base(HTTP_REQUEST, detail::parser_settings<request_parser>::get())
    {
        protocol_upgrade_handler_ = protocol_upgrade_handler;
    }

    request_parser(new_request_callback callback,
            protocol_upgrade_handler protocol_upgrade_handler)
        : parser_base(HTTP_REQUEST, detail::parser_settings<request_parser>::get()),
            callback_(callback)
    {
        protocol_upgrade_handler_ = protocol_upgrade_handler;
    }

    void set_max_request_rength(std::size_t max_length) // 0 means unlimited
            { request_length_limiter_.max_length(max_length); }

    inline std::size_t get_request_count() const noexcept { return parsed_requests_.size(); }

    inline request pop_request()
    {
        if (parsed_requests_.empty()) {
            throw std::out_of_range("requeest_parser::pop_request called "
                    "while no requests available");
        }
        request ret = std::move(parsed_requests_.front());
        parsed_requests_.pop_front();
        return ret;
    }

private:
    void throw_parse_error(const std::string& error_message) override
            { throw request_parse_error(error_message); }

private:
    friend struct detail::callbacks<request_parser>;

    int on_message_begin()
    {
        current_request_ = request();
        headers_assembler_.reset();
        request_length_limiter_.reset();
        return 0;
    }

    int on_url(const char* data, std::size_t length)
    {
        request_length_limiter_.check_length(length);
        current_request_.append_url(data, length);
        return 0;
    }

    int on_status(const char* data, std::size_t length)
    {
        assert(false); // not reached
        return 0;
    }

    int on_header_field(const char* data, std::size_t length)
    {
        request_length_limiter_.check_length(length);
        headers_assembler_.on_header_field(data, length);
        return 0;
    }

    int on_header_value(const char* data, std::size_t length)
    {
        request_length_limiter_.check_length(length);
        headers_assembler_.on_header_value(data, length);
        return 0;
    }

    int on_headers_complete()
    {
        headers_assembler_.on_headers_complete();
        return 0;
    }

    int on_body(const char* data, std::size_t length)
    {
        request_length_limiter_.check_length(length);
        current_request_.append_body(data, length);
        return 0;
    }

    int on_message_complete()
    {
        current_request_.method(static_cast<request_head::method_t>(p_.method));
        current_request_.http_version(http_version_t(p_.http_major, p_.http_minor));
        current_request_.keep_alive(http_should_keep_alive(&p_) != 0);
            parsed_requests_.push_back(std::move(current_request_));
        if (callback_) {
            callback_(*this);
        }
        return 0;
    }

    int on_chunk_header()
    {
        headers_assembler_.reset();
        return 0;
    }

    int on_chunk_complete()
    {
        headers_assembler_.on_headers_complete();
        return 0;
    }
};

class response_parser : public detail::parser_base
{
public:
    using new_response_callback = std::function<void(response_parser&)>;

private:
    response                  current_response_;
    detail::headers_assembler headers_assembler_        { current_response_ };
    new_response_callback     callback_;
    detail::length_limiter    response_length_limiter_  { [](std::size_t, std::size_t limit)
            {
                throw response_too_big("Response exceeded size limit of "
                        + std::to_string(limit));
            }};
    std::deque<response>      parsed_responses_;

public:
    response_parser()
        : parser_base(HTTP_RESPONSE, detail::parser_settings<response_parser>::get()) {}

    response_parser(new_response_callback callback)
        : parser_base(HTTP_RESPONSE, detail::parser_settings<response_parser>::get()),
            callback_(callback) {}

    response_parser(protocol_upgrade_handler proto_upgrade_handler)
        : parser_base(HTTP_RESPONSE, detail::parser_settings<response_parser>::get())
    {
        protocol_upgrade_handler_ = proto_upgrade_handler;
    }

    response_parser(new_response_callback callback,
            protocol_upgrade_handler proto_upgrade_handler)
        : parser_base(HTTP_RESPONSE, detail::parser_settings<response_parser>::get()),
            callback_(callback)
    {
        protocol_upgrade_handler_ = proto_upgrade_handler;
    }

    void set_max_response_length(std::size_t max_length) // 0 means unlimited
            { response_length_limiter_.max_length(max_length); }

    inline std::size_t get_response_count() const noexcept { return parsed_responses_.size(); }

    inline response pop_response()
    {
        if (parsed_responses_.empty()) {
            throw std::out_of_range("response_parser::pop_response called "
                    "while no responses available");
        }
        response ret = std::move(parsed_responses_.front());
        parsed_responses_.pop_front();
        return ret;
    }

private:
    void throw_parse_error(const std::string& error_message) override
            { throw response_parse_error(error_message); }

private:
    friend struct detail::callbacks<response_parser>;

    int on_message_begin()
    {
        current_response_ = response();
        headers_assembler_.reset();
        response_length_limiter_.reset();
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
        current_response_.append_status_text(data, length);
        return 0;
    }

    int on_header_field(const char* data, std::size_t length)
    {
        response_length_limiter_.check_length(length);
        headers_assembler_.on_header_field(data, length);
        return 0;
    }

    int on_header_value(const char* data, std::size_t length)
    {
        response_length_limiter_.check_length(length);
        headers_assembler_.on_header_value(data, length);
        return 0;
    }

    int on_headers_complete()
    {
        headers_assembler_.on_headers_complete();
        return 0;
    }

    int on_body(const char* data, std::size_t length)
    {
        response_length_limiter_.check_length(length);
        current_response_.append_body(data, length);
        return 0;
    }

    int on_message_complete()
    {
        current_response_.status_code(p_.status_code);
        current_response_.http_version(http_version_t(p_.http_major, p_.http_minor));
        current_response_.keep_alive(http_should_keep_alive(&p_) != 0);
        parsed_responses_.push_back(std::move(current_response_));
        current_response_ = response();
        if (callback_) {
            callback_(*this);
        }
        return 0;
    }

    int on_chunk_header()
    {
        headers_assembler_.reset();
        return 0;
    }

    int on_chunk_complete()
    {
        headers_assembler_.on_headers_complete();
        return 0;
    }
};


class big_request_parser : public detail::parser_base
{
public:
    using big_request_callback = std::function<void(const request_head &request_head,
            const char *body_part, std::size_t body_part_length, bool finished)>;

private:
    request_head              current_request_head_;
    detail::headers_assembler headers_assembler_ { current_request_head_ };
    big_request_callback      callback_;
    detail::length_limiter    headers_length_limiter_ { [](std::size_t, std::size_t limit)
            {
                throw request_headers_too_big("Request headers exceeded size limit of "
                        + std::to_string(limit));
            }};

public:
    big_request_parser(big_request_callback callback,
            protocol_upgrade_handler protocol_upgrade_handler = nullptr)
        : parser_base(HTTP_REQUEST, detail::parser_settings<big_request_parser>::get()),
            callback_(callback)
    {
        protocol_upgrade_handler_ = protocol_upgrade_handler;
    }

    void set_max_headers_length(std::size_t max_length) // 0 means unlimited
            { headers_length_limiter_.max_length(max_length); }

private:
    void throw_parse_error(const std::string& error_message) override
            { throw request_parse_error(error_message); }

private:
    friend struct detail::callbacks<big_request_parser>;

    int on_message_begin()
    {
        current_request_head_ = request_head();
        headers_assembler_.reset();
        headers_length_limiter_.reset();
        return 0;
    }

    int on_url(const char* data, std::size_t length)
    {
        headers_length_limiter_.check_length(length);
        current_request_head_.append_url(data, length);
        return 0;
    }

    int on_status(const char* data, std::size_t length)
    {
        assert(false); // not reached
        return 0;
    }

    int on_header_field(const char* data, std::size_t length)
    {
        headers_length_limiter_.check_length(length);
        headers_assembler_.on_header_field(data, length);
        return 0;
    }

    int on_header_value(const char* data, std::size_t length)
    {
        headers_length_limiter_.check_length(length);
        headers_assembler_.on_header_value(data, length);
        return 0;
    }

    int on_headers_complete()
    {
        headers_assembler_.on_headers_complete();
        current_request_head_.method(static_cast<request_head::method_t>(p_.method));
        current_request_head_.http_version(http_version_t(p_.http_major, p_.http_minor));
        current_request_head_.keep_alive(http_should_keep_alive(&p_) != 0);
        return 0;
    }

    int on_body(const char* data, std::size_t length)
    {
        callback_(current_request_head_, data, length, false);
        return 0;
    }

    int on_message_complete()
    {
        callback_(current_request_head_, nullptr, 0, true);
        return 0;
    }

    int on_chunk_header()
    {
        headers_assembler_.reset();
        return 0;
    }

    int on_chunk_complete()
    {
        headers_assembler_.on_headers_complete();
        return 0;
    }
};


class big_response_parser : public detail::parser_base
{
public:
    using big_response_callback = std::function<void(const response_head &response_head,
            const char *body_part, std::size_t body_part_length, bool finished)>;

private:
    response_head             current_response_head_;
    detail::headers_assembler headers_assembler_      { current_response_head_ };
    big_response_callback     callback_;
    detail::length_limiter    headers_length_limiter_ { [](std::size_t, std::size_t limit)
            {
                throw response_headers_too_big("Response headers exceeded size limit of "
                        + std::to_string(limit));
            }};

public:
    big_response_parser(big_response_callback callback,
            protocol_upgrade_handler proto_upgrade_handler = nullptr)
        : parser_base(HTTP_RESPONSE,
                    detail::parser_settings<big_response_parser>::get()),
            callback_(callback)
    {
        protocol_upgrade_handler_ = proto_upgrade_handler;
    }

    void set_max_headers_length(std::size_t max_length) // 0 means unlimited
            { headers_length_limiter_.max_length(max_length); }

private:
    void throw_parse_error(const std::string& error_message) override
            { throw response_parse_error(error_message); }

private:
    friend struct detail::callbacks<big_response_parser>;

    int on_message_begin()
    {
        current_response_head_ = response_head();
        headers_assembler_.reset();
        headers_length_limiter_.reset();
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
        headers_length_limiter_.check_length(length);
        current_response_head_.append_status_text(data, length);
        return 0;
    }

    int on_header_field(const char* data, std::size_t length)
    {
        headers_length_limiter_.check_length(length);
        headers_assembler_.on_header_field(data, length);
        return 0;
    }

    int on_header_value(const char* data, std::size_t length)
    {
        headers_length_limiter_.check_length(length);
        headers_assembler_.on_header_value(data, length);
        return 0;
    }

    int on_headers_complete()
    {
        headers_assembler_.on_headers_complete();
        current_response_head_.status_code(p_.status_code);
        current_response_head_.http_version(http_version_t(p_.http_major, p_.http_minor));
        current_response_head_.keep_alive(http_should_keep_alive(&p_) != 0);
        return 0;
    }

    int on_body(const char* data, std::size_t length)
    {
        callback_(current_response_head_, data, length, false);
        return 0;
    }

    int on_message_complete()
    {
        callback_(current_response_head_, nullptr, 0, true);
        return 0;
    }

    int on_chunk_header()
    {
        headers_assembler_.reset();
        return 0;
    }

    int on_chunk_complete()
    {
        headers_assembler_.on_headers_complete();
        return 0;
    }
};


struct url_t
{
    std::string schema;
    std::string host;
    std::string path;
    std::string query;
    std::string fragment;
    std::string userinfo;
    unsigned    port     = 0;
};


url_t parse_url(const std::string& input, bool is_connect = false)
{
    http_parser_url u;
    http_parser_url_init(&u);
    int err = http_parser_parse_url(
            input.c_str(), input.size(), int(is_connect), &u);
    if (err) {
        throw url_parse_error("Failed to parse this url: '" + input + "'");
    }

    url_t parsed_url;

    using field_t = std::pair<http_parser_url_fields, std::string url_t::*>;
    static const field_t string_fields[] = {
        { UF_SCHEMA,   &url_t::schema },
        { UF_HOST,     &url_t::host },
        { UF_PATH,     &url_t::path },
        { UF_QUERY,    &url_t::query },
        { UF_FRAGMENT, &url_t::fragment },
        { UF_USERINFO, &url_t::userinfo }
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


template<typename Stream>
Stream& operator<<(Stream& stream, const http::http_version_t& ver)
{
    stream << ver.to_string();
    return stream;
}

template<typename Stream>
Stream& operator<<(Stream& stream, http::request_head::method_t method)
{
    stream << http_method_str(method);
    return stream;
}

template<typename Stream>
Stream& operator<<(Stream& stream, const http::request& req)
{
    stream << "HTTP/" << req.http_version_ << " " << req.method_ << " request.\n"
            << "\tUrl: '" << req.url_ << "'\n"
            << "\tHeaders:\n";
    for (const auto& name_value_pair : req.headers_) {
        stream << "\t\t'" << name_value_pair.first << "': '" << name_value_pair.second << "'\n";
    }
    stream << "\tBody is " << req.body().size() << " bytes long.\n\tKeepAlive: "
            << (req.keep_alive_ ? "yes" : "no") << ".";
    return stream;
}

template<typename Stream>
Stream& operator<<(Stream& stream, const http::response& resp)
{
    stream << "HTTP/" << resp.http_version_ << " '" << resp.status_code_ << "' "
            << resp.status_text_ << " response.\n"
            << "\tHeaders:\n";
    for (const auto& name_value_pair : resp.headers_) {
        stream << "\t\t'" << name_value_pair.first << "': '" << name_value_pair.second << "'\n";
    }
    stream << "\tBody is " << resp.body().size() << " bytes long.\n\tKeepAlive: "
            << (resp.keep_alive_ ? "yes" : "no") << ".";
    return stream;
}

template<typename Stream>
Stream& operator<<(Stream& stream, const http::url_t& url)
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
