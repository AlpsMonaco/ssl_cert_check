#include "ssl_cert_check.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <asio.hpp>
#include <atomic>
#include <thread>
#include <mutex>
#include <iostream>

#ifndef _WIN32
#define SOCKET int
#endif

namespace scc
{
    void OpensslCheckCert(SOCKET handle, SSLCertInfo& ssl_cert_info)
    {
        auto meth = SSLv23_client_method();
        OpenSSL_add_ssl_algorithms();
        SSL_load_error_strings();
        auto ctx = SSL_CTX_new(meth);
        auto ssl = SSL_new(ctx);
        auto bio = BIO_new_socket(handle, BIO_NOCLOSE);
        SSL_set_bio(ssl, bio, bio);
        int count = 0;
        for (;;)
        {
            auto code = SSL_connect(ssl);
            if (code <= 0)
            {
                count++;
                if (count > 30)
                {
                    ssl_cert_info.status = kSocketConnectFailed;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            break;
        }
        X509* cert;
        cert = SSL_get_peer_certificate(ssl);
        ASN1_TIME* not_before = X509_get_notBefore(cert);
        ASN1_TIME* not_after = X509_get_notAfter(cert);
        int day = 0;
        int sec = 0;
        ASN1_TIME_diff(&day, &sec, not_before, NULL);
        ssl_cert_info.not_before.day = day;
        ssl_cert_info.not_before.sec = sec;
        ASN1_TIME_diff(&day, &sec, NULL, not_after);
        ssl_cert_info.not_after.day = day;
        ssl_cert_info.not_after.sec = sec;
        BIO_free_all(bio);
        X509_free(cert);
    }

    void AsyncCheckDomainSSL(asio::io_service& ios,
                             const std::vector<HttpsEndPoint>& endpoint_list,
                             std::atomic_size_t& cursor,
                             const SSLCertCheck::Callback& callback,
                             int connect_timeout)
    {
        auto index = cursor++;
        if (index >= endpoint_list.size()) return;
        const HttpsEndPoint& ep = endpoint_list[index];
        auto resolver_ptr = std::make_shared<asio::ip::tcp::resolver>(ios);
        resolver_ptr
            ->async_resolve(ep.domain, std::to_string(ep.port),
                            [&, resolver_ptr, connect_timeout](const std::error_code& ec,
                                                                   const asio::ip::tcp::resolver::results_type& results) -> void
                            {
                                if (ec || results.size() == 0)
                                {
                                    callback(SSLCertInfo{ep, {0, 0}, {0, 0}, kDomainResolveFailed});
                                    AsyncCheckDomainSSL(ios, endpoint_list, cursor, callback, connect_timeout);
                                }
                                else
                                {
                                    auto socket_ptr = std::make_shared<asio::ip::tcp::socket>(ios);
                                    auto timer_ptr = std::make_shared<asio::steady_timer>(ios);
                                    auto is_timeout = std::make_shared<bool>(false);
                                    timer_ptr->expires_from_now(std::chrono::seconds(connect_timeout));
                                    timer_ptr->async_wait([socket_ptr, timer_ptr, is_timeout](const std::error_code& ec) -> void
                                                          {
                                                              if (!ec)
                                                              {
                                                                  *is_timeout = true;
                                                                  socket_ptr->close();
                                                              }
                                                          });
                                    socket_ptr
                                        ->async_connect(results->endpoint(),
                                                        [&, socket_ptr, timer_ptr, is_timeout, connect_timeout](const std::error_code& ec) -> void
                                                        {
                                                            if (ec)
                                                            {
                                                                if (!(*is_timeout))
                                                                    timer_ptr->cancel();
                                                                callback(SSLCertInfo{ep, {0, 0}, {0, 0}, kSocketConnectFailed});
                                                            }
                                                            else
                                                            {
                                                                timer_ptr->cancel();
                                                                SSLCertInfo ssl_cert_info{ep, {0, 0}, {0, 0}, kSuccess};
                                                                SOCKET handle = socket_ptr->native_handle();
                                                                OpensslCheckCert(handle, ssl_cert_info);
                                                                callback(ssl_cert_info);
                                                            }
                                                            AsyncCheckDomainSSL(ios, endpoint_list, cursor, callback, connect_timeout);
                                                        });
                                }
                            });
    }

    std::vector<SSLCertInfo> CheckDomainListAll(const std::vector<HttpsEndPoint>& endpoint_list,
                                                int concurrency_num = 5,
                                                int thread_num = 5,
                                                int connect_timeout = 3)
    {
        asio::io_service ios;
        std::vector<SSLCertInfo> result;
        std::atomic_size_t cursor;
        std::mutex mu;
        SSLCertCheck::Callback cb = [&](const SSLCertInfo& info) -> void
        {
            mu.lock();
            result.emplace_back(info);
            mu.unlock();
        };
        for (size_t i = 0; i < concurrency_num; i++)
            AsyncCheckDomainSSL(ios, endpoint_list, cursor, cb, connect_timeout);
        std::vector<std::thread> thread_list;
        for (size_t i = 0; i < thread_num; i++)
        {
            thread_list.emplace_back(
                [&]() -> void
                {
                    ios.run();
                });
        }
        for (auto& t : thread_list)
        {
            t.join();
        }
        return result;
    }

    SSLCertCheck::SSLCertCheck()
        : check_endpoint_list_(),
          concurrency_num_(5),
          thread_num_(5),
          connect_timeout_(3)
    {
    }

    SSLCertCheck::~SSLCertCheck()
    {
    }

    void SSLCertCheck::Add(const HttpsEndPoint& endpoint)
    {
        check_endpoint_list_.emplace_back(endpoint);
    }

    void SSLCertCheck::Add(const std::string& domain, unsigned short port)
    {
        Add(HttpsEndPoint{domain, port});
    }

    std::vector<SSLCertInfo> SSLCertCheck::CheckAll()
    {
        return CheckDomainListAll(check_endpoint_list_, concurrency_num_, connect_timeout_);
    }

    void SSLCertCheck::AsyncCheck(const Callback& callback)
    {
        asio::io_service ios;
        std::atomic_size_t cursor;
        for (size_t i = 0; i < concurrency_num_; i++)
        {
            AsyncCheckDomainSSL(ios, check_endpoint_list_, cursor, callback, connect_timeout_);
        }
        std::vector<std::thread> thread_list;
        for (size_t i = 0; i < thread_num_; i++)
        {
            thread_list.emplace_back(
                [&]() -> void
                {
                    ios.run();
                });
        }
        for (auto& t : thread_list)
        {
            t.join();
        }
    }

    void SSLCertCheck::SetConcurrency(int num)
    {
        concurrency_num_ = num;
    }

    void SSLCertCheck::SetThreadNum(int num)
    {
        thread_num_ = num;
    }

    void SSLCertCheck::SetConnectTimeout(int seconds)
    {
        connect_timeout_ = seconds;
    }

    std::string SSLCertInfo::Message() const
    {
        switch (status)
        {
        case kSuccess:
            return "success";
        case kDomainResolveFailed:
            return "resolve domain dns failed";
        case kSocketConnectFailed:
            return "connect to target endpoint failed";
        default:
            return "unknown error";
        }
    }

    std::string SSLCertInfo::Message()
    {
        return const_cast<const SSLCertInfo&>(*this).Message();
    }

    bool SSLCertInfo::HasError() const
    {
        return status != kSuccess;
    }

    bool SSLCertInfo::HasError()
    {
        return const_cast<const SSLCertInfo&>(*this).HasError();
    }

    std::ostream& operator<<(std::ostream& os, const SSLCertInfo& info)
    {
        os << "domain -> " << info.endpoint.domain << std::endl
           << "port -> " << info.endpoint.port << std::endl
           << "not before -> " << info.not_before.day << " days," << info.not_before.sec << " secs" << std::endl
           << "not after -> " << info.not_after.day << " days," << info.not_after.sec << " secs";
        return os;
    }

} // namespace scc
