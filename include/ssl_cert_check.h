#ifndef __SSL_CERT_CHECK_H__
#define __SSL_CERT_CHECK_H__

#include <string>
#include <string_view>
#include <vector>
#include <ostream>
#include <functional>

namespace scc
{
    struct SSLCertTime
    {
        int days;
        int secs;
    };

    struct Endpoint
    {
        std::string address;
        unsigned short port;
    };

    enum SSLCertCheckStatus
    {
        kSuccess = 0,
        kResolveError,
        kConnectError,
        kHandshakeError,
    };

    struct SSLCertCheckResult
    {
        Endpoint endpoint;
        SSLCertTime not_before;
        SSLCertTime not_after;
        SSLCertCheckStatus status;
        friend std::ostream& operator<<(std::ostream& os, const SSLCertCheckResult& info);
        bool HasError() const;
        std::string_view Message() const;
    };

    class SSLCertCheck
    {
    public:
        using Callback = std::function<void(const SSLCertCheckResult&)>;
        SSLCertCheck();
        ~SSLCertCheck();
        void Add(const std::string_view& address, unsigned short port = 443);
        void BeginCheck(const Callback& callback);
        void SetConcurrency(size_t concurrency_num);
        void SetConnectTimeout(size_t milliseconds);

    protected:
        std::vector<Endpoint> endpoint_list_;
        size_t concurrency_num_;
        size_t connect_timeout_;
    };
} // namespace scc

#endif