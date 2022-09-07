#include "ssl_cert_check.h"
#include <iostream>
#include <fstream>
#include <string_view>

void PrintHelp()
{
    std::cout << R"(usage:
    ./ssl_cert_check <domain> [port]
    port is optional

example:
    ./ssl_cert_check www.google.com 
    ./ssl_cert_check www.google.com 443

-f  check domain from text file.
    ./ssl_cert_check -f <file_path>

example:
    ./ssl_cert_check -f domains.txt

file format:
endpoint per line in the text file,port is optional.
www.google.com
www.youtube.com 443
github.com
    )";
}

int CheckFromFile(int argc, char** argv)
{
    std::string file_name;
    std::string_view arg(argv[1]);
    if (arg == "-f")
    {
        if (argc < 3)
        {
            PrintHelp();
            return 1;
        }
        file_name = argv[2];
    }
    else
    {
        file_name.assign(arg.begin() + 2, arg.end());
    }
    std::ifstream ifs(file_name);
    if (!ifs.is_open())
    {
        PrintHelp();
        return 1;
    }
    std::string line;
    static constexpr std::string_view empty_strs = " \t\r\n";
    while (std::getline(ifs, line))
    {
        if (line.size() == 0) continue;
        size_t begin_index = line.find_first_not_of(empty_strs);
        size_t end_index = line.find_last_not_of(empty_strs);
        std::string_view sv(line.c_str() + begin_index, end_index - begin_index + 1);
        begin_index = sv.find_first_of(empty_strs);
        if (begin_index == std::string::npos)
        {
            std::cout << sv << std::endl;
        }
        else
        {
            end_index = sv.find_last_of(empty_strs);
            std::string_view domain(sv.data(), begin_index);
            std::string_view port(sv.data() + end_index + 1, sv.size() - end_index);
            std::cout << domain << std::endl;
            std::cout << port << std::endl;
        }
    }
    return 0;
}

int CheckFromArgs(int argc, char** argv)
{
    unsigned short port = 443;
    std::string domain = argv[1];
    if (argc > 2)
    {
        std::string port_str = argv[2];
        int argv_port = std::stoi(port_str);
        if (argv_port > 0 && argv_port < 65535)
            port = argv_port;
    }
    ssl_cert_check::SSLCertCheck check;
    check.Add(domain, port);
    auto result = check.Start();
    for (const auto& v : result)
    {
        if (v.HasError())
            std::cout << v.Message() << std::endl;
        else
            std::cout << v << std::endl;
    }
    return 0;
}

int main(int argc, char** argv)
{
    if (argc == 1)
    {
        PrintHelp();
        return 1;
    }
    std::string_view arg(argv[1]);
    if (arg.find("-f") != std::string::npos)
    {
        return CheckFromFile(argc, argv);
    }
    return CheckFromArgs(argc, argv);
}