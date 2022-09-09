#ifndef __SSL_CERT_CHECK_H__
#define __SSL_CERT_CHECK_H__

#include <vector>
#include <string>
#include <ostream>
#include <functional>

namespace scc
{
    struct SSLCertTime
    {
        int day;
        int sec;
    };

    struct HttpsEndPoint
    {
        std::string domain;
        unsigned short port;
    };

    enum SSLCertInfoStatus
    {
        kSuccess = 0,
        kDomainResolveFailed,
        kSocketConnectFailed,
    };

    struct SSLCertInfo
    {
        HttpsEndPoint endpoint;
        SSLCertTime not_before;
        SSLCertTime not_after;
        SSLCertInfoStatus status;

        std::string Message() const;
        std::string Message();
        bool HasError() const;
        bool HasError();
        friend std::ostream& operator<<(std::ostream& os, const SSLCertInfo& info);
    };

    class SSLCertCheck
    {
    public:
        using Callback = std::function<void(const SSLCertInfo&)>;

        SSLCertCheck();
        ~SSLCertCheck();

        void Add(const HttpsEndPoint& endpoint);
        void Add(const std::string& domain, unsigned short port = 443);
        void SetConcurrency(int num);
        void SetConnectTimeout(int seconds);
        void BeginCheck(const Callback& callback);

    protected:
        std::vector<HttpsEndPoint> endpoint_list_;
        int concurrency_num_;
        int connect_timeout_;
    };
} // namespace scc

#endif