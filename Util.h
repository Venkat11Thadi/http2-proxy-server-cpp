#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <WS2tcpip.h>

using namespace std;

#define BUFFER_SIZE 4096
#define ARRLEN(x)   (sizeof(x) / sizeof(x[0]))

typedef struct {
    const char* uri;
    struct http_parser_url* u;
    char* authority;
    char* path;
    size_t authoritylen;
    size_t pathlen;
    int32_t stream_id;
} http2_stream_data;

typedef struct {
    nghttp2_session* session;
    struct evdns_base* dnsbase;
    struct bufferevent* bev;
    http2_stream_data* stream_data;
} http2_session_data;

typedef enum _IO_OPERATION
{
    CLIENT_ACCEPT,
    RECV,
} IO_OPERATION, * PERIO_OPERATIONS;

typedef struct _PER_IO_DATA
{
    WSAOVERLAPPED overlapped;
    SOCKET sockfd;
    WSABUF wsaSendBuf, wsaRecvBuf;
    const CHAR* uri;
    CHAR sendBuffer[BUFFER_SIZE], recvBuffer[BUFFER_SIZE];
    DWORD bytesSend, bytesRecv;
    IO_OPERATION ioOperation;
    SSL* ssl;
    SSL_CTX* sslCtx;
    CHAR* hostname;
    BIO* rbio, * wbio;
    http2_session_data* session_data;
    BOOL recvFlag = FALSE;
} PER_IO_DATA, * LPPER_IO_DATA;

void initializeWinsock()
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

void initializeOpenSSL()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    cout << "OpenSSL initialized" << endl;
}

void openssl_cleanup()
{
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    printf("OpenSSL cleaned up.\n");
}

SSL_CTX* SSL_ctx_config()
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        printf("failed to create SSL_CTX object\n");
        free(ctx);
        return NULL;
    }
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    SSL_CTX_set_alpn_protos(ctx, (const unsigned char*)"\x02h2", 3);

    return ctx;
}

SOCKET createSocket(const char* hostname, int port)
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

static http2_stream_data* create_http2_stream_data(const char* uri,
    struct http_parser_url* u) {
    /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
    size_t extra = 7;
    http2_stream_data* stream_data = (http2_stream_data*)malloc(sizeof(http2_stream_data));
    if (stream_data)
    {
        stream_data->uri = uri;
        stream_data->u = u;
        stream_data->stream_id = -1;

        stream_data->authoritylen = u->field_data[UF_HOST].len;
        stream_data->authority = (char*)malloc(stream_data->authoritylen + extra);
        memcpy(stream_data->authority, &uri[u->field_data[UF_HOST].off],
            u->field_data[UF_HOST].len);

        if (u->field_set & (1 << UF_PORT))
        {
            stream_data->authoritylen +=
                (size_t)snprintf(stream_data->authority + u->field_data[UF_HOST].len,
                    extra, ":%u", u->port);
        }

        /* If we don't have path in URI, we use "/" as path. */
        stream_data->pathlen = 1;
        if (u->field_set & (1 << UF_PATH))
        {
            stream_data->pathlen = u->field_data[UF_PATH].len;
        }
        if (u->field_set & (1 << UF_QUERY))
        {
            /* +1 for '?' character */
            stream_data->pathlen += (size_t)(u->field_data[UF_QUERY].len + 1);
        }

        stream_data->path = (char*)malloc(stream_data->pathlen);
        if (u->field_set & (1 << UF_PATH))
        {
            memcpy(stream_data->path, &uri[u->field_data[UF_PATH].off],
                u->field_data[UF_PATH].len);
        }
        else
        {
            stream_data->path[0] = '/';
        }
        if (u->field_set & (1 << UF_QUERY))
        {
            stream_data->path[stream_data->pathlen - u->field_data[UF_QUERY].len - 1] =
                '?';
            memcpy(stream_data->path + stream_data->pathlen -
                u->field_data[UF_QUERY].len,
                &uri[u->field_data[UF_QUERY].off], u->field_data[UF_QUERY].len);
        }
    }
    return stream_data;
}

static void delete_http2_stream_data(http2_stream_data* stream_data) {
    free(stream_data->path);
    free(stream_data->authority);
    free(stream_data);
}

/* Initializes |session_data| */
static http2_session_data*
create_http2_session_data() {
    http2_session_data* session_data = (http2_session_data*)malloc(sizeof(http2_session_data));
    if (session_data)
    {
        memset(session_data, 0, sizeof(http2_session_data));
    }
    return session_data;
}

static void delete_http2_session_data(http2_session_data* session_data) {
    nghttp2_session_del(session_data->session);
    session_data->session = NULL;
    if (session_data->stream_data) {
        delete_http2_stream_data(session_data->stream_data);
        session_data->stream_data = NULL;
    }
    free(session_data);
}

/* Serialize the frame and send (or buffer) the data. */
static int session_send(http2_session_data* session_data) {
    int rv;

    rv = nghttp2_session_send(session_data->session);
    if (rv != 0) {
        printf("Fatal error: %s\n", nghttp2_strerror(rv));
        return -1;
    }
    printf("session_send callback\n");
    return 0;
}


static void print_header(FILE* f, const uint8_t* name, size_t namelen,
    const uint8_t* value, size_t valuelen) {
    fwrite(name, 1, namelen, f);
    fprintf(f, ": ");
    fwrite(value, 1, valuelen, f);
    fprintf(f, "\n");
}

/* Print HTTP headers to |f|. Please note that this function does not
   take into account that header name and value are sequence of
   octets, therefore they may contain non-printable characters. */
static void print_headers(FILE* f, nghttp2_nv* nva, size_t nvlen) {
    size_t i;
    for (i = 0; i < nvlen; ++i) {
        print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
    }
    fprintf(f, "\n");
}

/* nghttp2_send_callback2. Here we transmit the |data|, |length|
   bytes, to the network. */
static nghttp2_ssize send_callback(nghttp2_session* session,
    const uint8_t* data, size_t length,
    int flags, void* user_data) {
    int bio_read, ssl_write;
    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
    char* buffer[BUFFER_SIZE] = { '\0' };
    (void)session;
    (void)flags;

    printf("[+]send callback\n");

    ssl_write = SSL_write(ioData->ssl, data, length);
    if (ssl_write > 0)
    {
        printf("[+]ssl_write: %d\n", ssl_write);
        bio_read = BIO_read(ioData->wbio, buffer, BUFFER_SIZE);
        
        if (bio_read > 0)
        {
            printf("[+]bio_read: %d\n", bio_read);
            memcpy(ioData->sendBuffer, buffer, bio_read);
            ioData->ioOperation = RECV;
            //printf("sendbuffer - %d, recvbuffer - %d\n", strlen(ioData->sendBuffer), strlen(ioData->recvBuffer));
            ioData->wsaSendBuf.len = bio_read;
            
            if (WSASend(ioData->sockfd, &ioData->wsaSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
            {
                int error = WSAGetLastError();
                printf("WSASend() failed: %d\n", error);  
                if (error != WSA_IO_PENDING)
                {
                    printf("Failed to send response: %d\n", error);
                    closesocket(ioData->sockfd);
                    delete ioData;
                    return 0;
                }
            }
            else
            {
                printf("[+]WSASend: %d\n", ioData->bytesSend);
            }
        }
    }

    return (nghttp2_ssize)length;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session* session,
    const nghttp2_frame* frame, const uint8_t* name,
    size_t namelen, const uint8_t* value,
    size_t valuelen, uint8_t flags, void* user_data) {
    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
    (void)session;
    (void)flags;

    printf("[+]on header callback\n");

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            ioData->session_data->stream_data->stream_id == frame->hd.stream_id) {
            /* Print response headers for the initiated request. */
            print_header(stderr, name, namelen, value, valuelen);
            break;
        }
    }
    return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
   started to receive header block. */
static int on_begin_headers_callback(nghttp2_session* session,
    const nghttp2_frame* frame,
    void* user_data) {
    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
    (void)session;

    printf("[+]on begin headers callback\n");

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            ioData->session_data->stream_data->stream_id == frame->hd.stream_id) {
            fprintf(stderr, "Response headers for stream ID=%d:\n",
                frame->hd.stream_id);
        }
        break;
    }
    return 0;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
   received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session* session,
    const nghttp2_frame* frame, void* user_data) {
    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
    (void)session;

    printf("[+]on frame recv callback\n");

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            ioData->session_data->stream_data->stream_id == frame->hd.stream_id) {
            fprintf(stderr, "All headers received\n");
        }
        break;
    case NGHTTP2_DATA:
    {
        printf("[+]Data frame recevied\n");
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
            printf("[+]Response received\n");
        }
    }
    }
    
    return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
   received from the remote peer. In this implementation, if the frame
   is meant to the stream we initiated, print the received data in
   stdout, so that the user can redirect its output to the file
   easily. */
static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags,
    int32_t stream_id, const uint8_t* data,
    size_t len, void* user_data) {
    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
    (void)session;
    (void)flags;

    printf("[+]on data chunk recv callback\n");

    if (ioData->session_data->stream_data->stream_id == stream_id) {
        // print to stdout
        fwrite(data, 1, len, stdout);
    }
    
    return 0;
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
   closed. This example program only deals with 1 HTTP request (1
   stream), if it is closed, we send GOAWAY and tear down the
   session */
static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id,
    uint32_t error_code, void* user_data) {
    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
    int rv;

    printf("[+]on stream close callback\n");

    if (ioData->session_data->stream_data->stream_id == stream_id) {
        fprintf(stderr, "Stream %d closed with error_code=%u\n", stream_id,
            error_code);
        rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
        if (rv != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    
    return 0;
}

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE,     sizeof(NAME) - 1,                   \
    VALUELEN,        NGHTTP2_NV_FLAG_NONE,                                     \
  }

#define MAKE_NV2(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,                 \
    sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,                                   \
  }

static void submit_request(http2_session_data* session_data)
{
    int32_t stream_id;
    http2_stream_data* stream_data = session_data->stream_data;
    const char* uri = stream_data->uri;
    const struct http_parser_url* u = stream_data->u;
    nghttp2_nv hdrs[] = {
      MAKE_NV2(":method", "GET"),
      MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],
              u->field_data[UF_SCHEMA].len),
      MAKE_NV(":authority", stream_data->authority, stream_data->authoritylen),
      MAKE_NV(":path", stream_data->path, stream_data->pathlen) };
    fprintf(stderr, "Request headers:\n");
    print_headers(stderr, hdrs, ARRLEN(hdrs));
    stream_id = nghttp2_submit_request2(session_data->session, NULL, hdrs,
        ARRLEN(hdrs), NULL, stream_data);
    if (stream_id < 0) {
        printf("Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
    }
    else
    {
        printf("[+]HTTP request submitted\n");
    }

    stream_data->stream_id = stream_id;
}