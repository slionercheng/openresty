# ngx_http_anp_module

This is an OpenResty/Nginx module that implements the ANP protocol, which is based on HTTP.

## Description

The ANP module intercepts HTTP requests at the access phase, processes HTTP-related information, and performs custom logic before allowing the request to proceed to other phases. This module is designed to be a prerequisite for other functionality - it must complete successfully before other modules can process the request.

## Installation

### Method 1: Compile with OpenResty

1. Add the module to OpenResty's configure command:

```bash
./configure --prefix=/usr/local/openresty \
            --add-module=bundle/ngx_http_anp_module \
            [other options...]
```

2. Compile and install OpenResty:

```bash
make
make install
```

### Method 2: Dynamic Module (Nginx 1.9.11+)

1. Build the module as a dynamic module:

```bash
./configure --prefix=/usr/local/openresty \
            --add-dynamic-module=bundle/ngx_http_anp_module \
            [other options...]
```

2. Compile and install:

```bash
make
make install
```

3. Load the module in your nginx.conf:

```nginx
load_module modules/ngx_http_anp_module.so;
```

## Configuration

Add the following directive to your nginx.conf to enable the ANP module:

```nginx
server {
    listen 80;
    server_name example.com;
    
    # Enable ANP module
    anp on;
    
    location / {
        # Your location configuration
    }
}
```

## Directives

### anp

| Syntax  | `anp on|off` |
|---------|-------------|
| Default | `anp off`    |
| Context | http, server, location |

Enables or disables the ANP module processing.

## How It Works

When enabled, the ANP module:

1. Intercepts HTTP requests at the access phase
2. Logs detailed information about the request (method, URI, headers, etc.)
3. Processes the request according to ANP protocol rules
4. Adds an `X-ANP-Processed: true` header to the response
5. Allows the request to continue to the next phase if processing is successful

## License

This module is licensed under the same terms as OpenResty.
