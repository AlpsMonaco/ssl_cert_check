# ssl_cert_check
c++ https ssl certificate expiration time check tool.

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

## Library Usage
```c++
#include "ssl_cert_check.h"
...
scc::SSLCertCheck check;
// add target endpoint,default port is 443;
check.Add("google.com");
check.Add("www.google.com",443);
auto result = check.Start();
for (const auto& v : result)
{
    if (v.HasError())
        std::cout << v.Message() << std::endl;
    else
        std::cout << v << std::endl;
}
```

## Compile

use `CMake` to compile.

```bash
# linux
mkdir build ; cd build ; cmake .. ; make ;
```

For `Linux` user,you need to install `openssl` in your system.  
For `Windows` user,there are `openssl` header files and precompiled `openssl` lib in this repository.  
You could simply `CMake` it using `Visual Studio`.But if the compile has any unexpected error,you might need to change the `openssl`  
dependency yourself.  


