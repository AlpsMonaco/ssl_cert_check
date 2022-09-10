#include <iostream>
#include <chrono>
#include <iomanip>
#include <thread>
#include "asio.hpp"

#ifdef _WIN32
void localtime_r(const time_t* tt, tm* tm)
{
    localtime_s(tm, tt);
}
#endif

template <typename T>
void Println(const T& t)
{
    std::stringstream ss;
    auto tt = std::time(nullptr);
    struct tm tm;
    localtime_r(&tt, &tm);
    ss << tm.tm_year + 1900 << "-"
       << std::setfill('0') << std::setw(2) << tm.tm_mon + 1 << "-"
       << std::setfill('0') << std::setw(2) << tm.tm_mday << ' '
       << std::setfill('0') << std::setw(2) << tm.tm_hour << ':'
       << std::setfill('0') << std::setw(2) << tm.tm_min << ':'
       << std::setfill('0') << std::setw(2) << tm.tm_sec << ' '
       << t << std::endl;
    std::cout << ss.str();
}

int main(int argc, char** argv)
{
    asio::io_service ios;
    asio::ip::tcp::resolver r(ios);
    std::error_code ec;

    std::thread([]() -> void
                {
                    asio::io_service ios;
                    asio::ip::tcp::resolver r(ios);
                    std::error_code ec;
                    for (;;)
                    {
                        auto st = std::chrono::system_clock::now();
                        auto results = r.resolve(asio::ip::tcp::v4(), "google.com", "443", ec);
                        if (ec)
                        {
                            std::cout << ec << std::endl;
                            return;
                        }
                        auto ed = std::chrono::system_clock::now();
                        Println(std::string("resolve time:") + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(ed - st).count()) + "ms");
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                })
        .detach();
    for (;;)
    {
        auto st = std::chrono::system_clock::now();
        auto results = r.resolve(asio::ip::tcp::v4(), "hotgamehl.com", "443", ec);
        if (ec)
        {
            std::cout << ec << std::endl;
            return 1;
        }
        auto ed = std::chrono::system_clock::now();
        Println(std::string("resolve time:") + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(ed - st).count()) + "ms");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}