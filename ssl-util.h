#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <thread>
#include <vector>
#include <regex>
#include <map>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#define BUFFER_SIZE 4096
#define PORT 8080

using namespace std;

typedef struct {
    const char* uri;
    struct http_parser_url* u;
    char* authority;
    char* path;
    size_t authoritylen;
    size_t pathlen;

    std::vector<nghttp2_nv> headers;
    string body;
    
    int32_t stream_id;

    BOOL isBodyRecv;
} http2_client_stream_data;

typedef struct {
    nghttp2_session* session;
	std::map<int32_t, http2_client_stream_data*> stream_map;
    http2_client_stream_data* stream_data;
} http2_client_session_data;

struct app_context;
typedef struct app_context app_context;

typedef struct http2_server_stream_data {
    struct http2_server_stream_data* prev, * next;
    char* request_path;
    int32_t stream_id;
    int fd;

    size_t response_body_offset = 0;

    std::vector<nghttp2_nv> headers;
    string body;

    ~http2_server_stream_data() {
        for (auto& nv : headers) {
            free(nv.name);
            free(nv.value);
        }
    }
} http2_server_stream_data;

typedef struct http2_server_session_data {
    struct http2_server_stream_data root;
    SSL_CTX* ssl_ctx;
    SSL* ssl;
    nghttp2_session* session;
    char* client_addr;
    int32_t last_stream_id;
} http2_server_session_data;

typedef struct {
    const char* data;
    size_t length;
    size_t offset;
} buffer_source;

typedef enum _IO_OPERATION
{
    CLIENT_ACCEPT,
    HTTP_S_RECV,
    HTTP_S_SEND,
    HTTP_C_RECV,
    HTTP_C_SEND,
    CLIENT_IO,
    SERVER_IO,
    IO,
    SERVER_SSL_HANDSHAKE,
    CLIENT_SSL_HANDSHAKE,
    REQUEST_RECV,
    SERVER_SEND,
    CLIENT_SEND
} IO_OPERATION,
* PERIO_OPERATIONS;

typedef enum state
{
    NONE,
    CLIENT,
    SERVER,
    FORWARD_RESP,
    STREAM_CLOSE
} STATE;

static INT ID = 0;
http2_server_session_data* g_proxy_session_data;
SSL_CTX* g_proxy_ctx = NULL;
SSL* g_proxy_ssl = NULL;
sockaddr* g_addr = NULL;
size_t g_addrlen = 0;
HANDLE g_completionPort;
SOCKET g_proxySocket;
X509* rootCACert;
EVP_PKEY* rootCAKey;
BOOL detailLog = TRUE;

void InitializeWinsock()
{
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        cerr << "[-]WSAStartup failed - " << result << endl;
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "Winsock initialized" << endl;
    }
}

void InitializeOpenSSL()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    cout << "OpenSSL initialized" << endl;
}

void OpensslCleanup()
{
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    printf("OpenSSL cleaned up.\n");
}

SOCKET StartListen(INT port)
{
    SOCKET sockfd;

    struct addrinfo hints, * res, * rp;
    ZeroMemory(&hints, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // For wildcard IP address

    int rv = getaddrinfo(NULL, to_string(port).c_str(), &hints, &res);
    if (rv != 0)
    {
        printf("[-]getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }

    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        sockfd = WSASocket(rp->ai_family, rp->ai_socktype, rp->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sockfd == INVALID_SOCKET)
        {
            printf("[-]WSASocket error\n");
            continue;
        }
        int opt = 1;
        int size = sizeof(int);
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, size);
        if (bind(sockfd, rp->ai_addr, (int)rp->ai_addrlen) != SOCKET_ERROR)
        {
            g_addr = rp->ai_addr;
            g_addrlen = rp->ai_addrlen;
            break;
        }
    }

    if (rp == NULL)
    {
        fprintf(stderr, "Failed to bind\n");
        exit(2);
    }

    freeaddrinfo(res);

    if (listen(sockfd, SOMAXCONN) == SOCKET_ERROR)
    {
        printf("[-]Unable to listen: %d\n", WSAGetLastError());
        closesocket(sockfd);
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("[+]Listening on port %d...\n", port);
    }

    return sockfd;
}

// parsing connect request to obtain hostname and port
bool ParseConnectRequest(const string& request, string& hostname, int& port)
{
    size_t pos = request.find("CONNECT ");
    if (pos == string::npos)
        return false;
    pos += 8;
    size_t end = request.find(" ", pos);
    if (end == string::npos)
        return false;

    string hostport = request.substr(pos, end - pos);
    pos = hostport.find(":");
    if (pos == string::npos)
        return false;

    hostname = hostport.substr(0, pos);
    port = stoi(hostport.substr(pos + 1));
    return true;
}

// forming TCP connection with the target server
SOCKET ConnectToTarget(const string& hostname, int port)
{
    SOCKET sock;
    struct addrinfo hints, * res, * p;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), port_str, &hints, &res) != 0)
    {
        cerr << "getaddrinfo" << endl;
        exit(EXIT_FAILURE);
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        sock = WSASocket(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
        {
            cerr << "[-]Invalid socket" << endl;
            continue;
        }

        if (WSAConnect(sock, p->ai_addr, p->ai_addrlen, NULL, NULL, NULL, NULL) == SOCKET_ERROR)
        {
            closesocket(sock);
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        cerr << "[-]Unable to connect to target server: " << hostname << endl;
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);
    return sock;
}

string ExtractHost(const string& request)
{
    size_t pos = request.find("Host: ");
    if (pos == string::npos)
        return "";
    pos += 6;
    size_t end = request.find("\r\n", pos);
    return request.substr(pos, end - pos);
}

std::string ExtractHostWithPort(const std::string& request) {
    std::regex requestRegex(R"(^(GET|CONNECT)\s+(\S+)\s+HTTP/\d\.\d)", std::regex::icase);
    std::smatch match;

    if (std::regex_search(request, match, requestRegex)) {
        std::string method = match[1].str();
        std::string host = match[2].str();

        return host;
    }

    return "";
}


SOCKET CreateSocket(const char* hostname, int port)
{
    SOCKET sock;
    struct addrinfo hints, * res, * p;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port_str, &hints, &res) != 0)
    {
        cerr << "getaddrinfo" << endl;
        exit(EXIT_FAILURE);
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        sock = WSASocket(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET)
        {
            cerr << "Invalid socket" << endl;
            continue;
        }

        if (WSAConnect(sock, p->ai_addr, p->ai_addrlen, NULL, NULL, NULL, NULL) == SOCKET_ERROR)
        {
            closesocket(sock);
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        cerr << "Unable to connect to target server: " << hostname << endl;
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);
    return sock;
}

static int alpn_select_proto_cb(SSL* ssl, const unsigned char** out,
    unsigned char* outlen, const unsigned char* in,
    unsigned int inlen, void* arg) {
    int rv;
    (void)ssl;
    (void)arg;

    rv = nghttp2_select_alpn(out, outlen, in, inlen);

    if (rv != 1) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
}

SSL_CTX* server_SSL_CTX()
{
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx)
    {
        printf("[-]Could not create server SSL CTX (%s)\n", ERR_error_string(ERR_get_error(), NULL));
    }

    SSL_CTX_set_options(ssl_ctx,
        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, NULL);

    return ssl_ctx;
}

SSL_CTX* client_SSL_CTX()
{
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx)
    {
        printf("[-]Could not create client SSL CTX (%s)\n", ERR_error_string(ERR_get_error(), NULL));
    }

    SSL_CTX_set_options(ssl_ctx,
        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char*)"\x02h2", 3);

    return ssl_ctx;
}

/* Create SSL object */
static SSL* create_ssl(SSL_CTX* ssl_ctx) {
    SSL* ssl;
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        printf("[-]Could not create SSL/TLS session object: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    }
    return ssl;
}

ASN1_INTEGER* generate_serial()
{
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    if (!serial)
    {
        cerr << "ASN1_INTEGER_new failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Generate a random 64-bit integer for the serial number
    uint64_t serial_number = 0;
    if (!RAND_bytes((unsigned char*)&serial_number, sizeof(serial_number)))
    {
        cerr << "RAND_bytes failed" << endl;
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        exit(EXIT_FAILURE);
    }

    // Convert the random number to ASN1_INTEGER
    if (!ASN1_INTEGER_set_uint64(serial, serial_number))
    {
        cerr << "ASN1_INTEGER_set_uint64 failed" << endl;
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        exit(EXIT_FAILURE);
    }

    return serial;
}

X509* create_certificate(X509* ca_cert, EVP_PKEY* ca_pkey, EVP_PKEY* pkey, string hostname)
{
    BOOL isRootCACert = FALSE;
    X509* cert = X509_new();
    if (!cert)
    {
        cerr << "X509_new failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    std::string saName("DNS:");
    saName.append(hostname);

    X509_set_version(cert, 2);

    ASN1_INTEGER* serial = generate_serial();
    X509_set_serialNumber(cert, serial);

    ASN1_INTEGER_free(serial);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Proxy", -1, -1, 0);

    // Set CN
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)hostname.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    X509_set_subject_name(cert, name);

    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL, (int)NID_subject_alt_name, saName.data());
    if (!ext)
    {
        return NULL;
    }

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    if (isRootCACert)
    {
        // Add NID_basic_constraints extension for firefox
        ext = X509V3_EXT_conf_nid(NULL, NULL, (int)NID_basic_constraints, const_cast <char*>("CA:TRUE"));
        if (ext)
        {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    if (!X509_sign(cert, ca_pkey, EVP_sha256()))
    {
        cerr << "[-]Error signing certificate" << endl;
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        exit(EXIT_FAILURE);
    }

    return cert;
}

char* strndup(const char* s, size_t n) {
    char* p = (char*)malloc(n + 1);
    if (!p) return nullptr;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}
