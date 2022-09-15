#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <asio.hpp>
#include <thread>
#include <mutex>
#include <dns_query/dns_query.h>
#include "ssl_cert_check.h"

#ifndef _WIN32
#define SOCKET int
#endif

namespace scc
{
    void OpensslCheckCert(SOCKET handle, SSLCertCheckResult& info)
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
                    info.status = kHandshakeError;
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
        info.not_before.days = day;
        info.not_before.secs = sec;
        ASN1_TIME_diff(&day, &sec, NULL, not_after);
        info.not_after.days = day;
        info.not_after.secs = sec;
        BIO_free_all(bio);
        X509_free(cert);
    }

    bool IsDomain(const std::string_view& sv)
    {
        for (const auto& c : sv)
            if (c > 57) return true;
        return false;
    }

    std::ostream& operator<<(std::ostream& os, const SSLCertCheckResult& info)
    {
        os << "address -> " << info.endpoint.address << std::endl
           << "port -> " << info.endpoint.port << std::endl
           << "not before -> " << info.not_before.days << " days," << info.not_before.secs << " secs" << std::endl
           << "not after -> " << info.not_after.days << " days," << info.not_after.secs << " secs";
        return os;
    }

    class AsyncSSLCertTask
    {
    public:
        AsyncSSLCertTask(const SSLCertCheck::Callback& callback, const std::vector<Endpoint>& endpoint_list,
                         size_t concurrency_num, size_t connect_timeout)
            : socket_ios_(),
              timer_ios_(),
              socket_work_ptr_(nullptr),
              timer_work_ptr_(nullptr),
              concurrency_num_(concurrency_num),
              connect_timeout_(connect_timeout),
              cursor_(0),
              done_cursor_(0),
              endpoint_list_(endpoint_list),
              callback_(callback)
        {
        }
        ~AsyncSSLCertTask() {}

        void Start()
        {
            if (socket_work_ptr_ != nullptr) delete socket_work_ptr_;
            socket_work_ptr_ = new asio::io_service::work(socket_ios_);
            if (timer_work_ptr_ != nullptr) delete timer_work_ptr_;
            timer_work_ptr_ = new asio::io_service::work(timer_ios_);
            std::vector<std::thread> thread_list;
            for (size_t i = 0; i < concurrency_num_; i++)
            {
                AsyncCheckNext();
                thread_list.emplace_back(
                    std::thread([&]() -> void
                                {
                                    socket_ios_.run();
                                }));
                thread_list.emplace_back(
                    std::thread([&]() -> void
                                {
                                    timer_ios_.run();
                                }));
            }
            thread_list.emplace_back(std::thread(
                [&]() -> void
                {
                    dns_query_.Run(false);
                }));
            for (;;)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                size_t num = done_cursor_;
                if (num >= endpoint_list_.size())
                {
                    UnlockIOService();
                    break;
                }
            }
            dns_query_.Stop();
            for (auto& t : thread_list)
                t.join();
        }

        void Stop()
        {
            UnlockIOService();
            socket_ios_.stop();
            timer_ios_.stop();
        }

    protected:
        void UnlockIOService()
        {
            if (socket_work_ptr_ != nullptr) delete socket_work_ptr_;
            if (timer_work_ptr_ != nullptr) delete timer_work_ptr_;
        }

        void AsyncCheckNext()
        {
            size_t index = cursor_++;
            if (index >= endpoint_list_.size()) return;
            const auto& endpoint = endpoint_list_[index];
            if (!IsDomain(endpoint.address))
                AsyncCheckIP(asio::ip::tcp::endpoint(
                                 asio::ip::address::from_string(endpoint.address), endpoint.port),
                             endpoint.address);
            else
            {
                AsyncCheckDomain(endpoint);
            }
        }

        void AsyncCheckDomain(const Endpoint& endpoint)
        {
            mutex_.lock();
            dns_query_.AsyncResolve(endpoint.address, [&](const dns::Result& result) -> void
                                    {
                                        if (result.HasError())
                                        {
                                            callback_(
                                                SSLCertCheckResult{
                                                    {endpoint.address, endpoint.port},
                                                    {0, 0},
                                                    {0, 0},
                                                    kConnectError,
                                                });
                                            done_cursor_++;
                                            AsyncCheckNext();
                                            return;
                                        }
                                        if (result.Begin() != dns::Result::iterator_end)
                                        {
                                            AsyncCheckIP(asio::ip::tcp::endpoint(
                                                             asio::ip::address::from_string(std::string(*result.Begin())),
                                                             endpoint.port),
                                                         std::string(result.Name()));
                                        }
                                        else
                                        {
                                            done_cursor_++;
                                            AsyncCheckNext();
                                        }
                                    });
            mutex_.unlock();
        }

        void AsyncCheckIP(const asio::ip::tcp::endpoint& endpoint, const std::string& address)
        {
            auto socket_ptr = std::make_shared<asio::ip::tcp::socket>(socket_ios_);
            auto timer_ptr = std::make_shared<asio::steady_timer>(timer_ios_);
            timer_ptr->expires_from_now(std::chrono::milliseconds(connect_timeout_));
            timer_ptr->async_wait([socket_ptr](const std::error_code& ec) -> void
                                  {
                                      if (!ec) socket_ptr->cancel();
                                  });
            socket_ptr->async_connect(endpoint,
                                      [&, timer_ptr, endpoint = endpoint, socket_ptr, address = address](const std::error_code& ec)
                                          -> void
                                      {
                                          if (ec)
                                          {
                                              callback_(
                                                  SSLCertCheckResult{
                                                      {address, endpoint.port()},
                                                      {0, 0},
                                                      {0, 0},
                                                      kConnectError,
                                                  });
                                          }
                                          else
                                          {
                                              timer_ptr->cancel();
                                              SSLCertCheckResult info{
                                                  {address, endpoint.port()},
                                                  {0, 0},
                                                  {0, 0},
                                                  kSuccess,
                                              };
                                              int handle = socket_ptr->native_handle();
                                              OpensslCheckCert(handle, info);
                                              callback_(info);
                                          }
                                          done_cursor_++;
                                          AsyncCheckNext();
                                      });
        }

        asio::io_service socket_ios_;
        asio::io_service timer_ios_;
        asio::io_service::work* socket_work_ptr_;
        asio::io_service::work* timer_work_ptr_;
        size_t concurrency_num_;
        size_t connect_timeout_;
        std::atomic_size_t cursor_;
        std::atomic_size_t done_cursor_;
        const std::vector<Endpoint>& endpoint_list_;
        const SSLCertCheck::Callback& callback_;
        dns::DNSQuery dns_query_;
        std::mutex mutex_;
    };

    SSLCertCheck::SSLCertCheck()
        : endpoint_list_()
    {
    }

    SSLCertCheck::~SSLCertCheck()
    {
    }

    void SSLCertCheck::SetConcurrency(size_t concurrency_num)
    {
        concurrency_num_ = concurrency_num;
    }

    void SSLCertCheck::Add(const std::string_view& address, unsigned short port)
    {
        endpoint_list_.emplace_back(Endpoint{std::string(address), port});
    }

    void SSLCertCheck::BeginCheck(const Callback& callback)
    {
        AsyncSSLCertTask task(callback, endpoint_list_, concurrency_num_, connect_timeout_);
        task.Start();
    }

    void SSLCertCheck::SetConnectTimeout(size_t milliseconds)
    {
        connect_timeout_ = milliseconds;
    }

    bool SSLCertCheckResult::HasError() const
    {
        return status != kSuccess;
    }

    std::string_view SSLCertCheckResult::Message() const
    {
        switch (status)
        {
        case kSuccess:
            return "success";
        case kResolveError:
            return "resolve target domain name failed";
        case kConnectError:
            return "connect to target endpoint failed";
        case kHandshakeError:
            return "handshake with target endpoint failed";
        default:
            return "unknown";
        }
    }

} // namespace scc
