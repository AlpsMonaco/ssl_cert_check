# ssl_cert_check
c++ https ssl certificate expiration time and info check tool.


## Library Usage
```c++
#include "ssl_cert_check.h"
...
scc::SSLCertCheck check;
// add target endpoint,default port is 443;
check.Add("google.com");
check.Add("www.google.com",443);
check.BeginCheck(
    [&](const scc::SSLCertCheckResult& result) -> void
    {
        if (result.HasError())
            std::cout << "error:" << result.Message() << std::endl;
        std::cout << v << std::endl;
    });
```

## Cli usage
```
./ssl_cert_check google.com
```
or specify port
```
./ssl_cert_check google.com 443
```

output:
```
domain -> google.com
port -> 443
not before -> 209 days,11390 secs
not after -> 170 days,75009 secs
```

you could also specify domains to resolve by file,a domain (and a port) per line.  
`-f` arg to specify file.

```domains.txt```
```
google.com 443
www.google.com
youtube.com 444
cloudflare.com
```
```
./ssl_cert_check -fdomains.txt
```
```
----------------------------------------
domain -> google.com
port -> 443
not before -> 745 days,12886 secs
not after -> 24 days,30314 secs
----------------------------------------
domain -> www.google.com
port -> 443
not before -> 745 days,0 secs
not after -> 24 days,30314 secs
----------------------------------------
error:connect to target endpoint failed
domain -> youtube.com
port -> 444
not before -> 0 days,0 secs
not after -> 0 days,0 secs
----------------------------------------
domain -> cloudflare.com
port -> 443
not before -> 745 days,0 secs
not after -> 24 days,30314 secs
----------------------------------------
```

## Compile

1. Init all git module
```bash
git submodule update --init --recursive
```

2. use `CMake` to compile.

```bash
# linux
mkdir build ; cd build ; cmake .. ; make ;
```

For `Linux` user,you need to install `openssl` in your system.  
For `Windows` user,there are `openssl` header files and precompiled `openssl` lib in this repository.  
You could simply `CMake` it using `Visual Studio`.But if the compile has any unexpected error,you might need to change the `openssl`  
dependency yourself.  
