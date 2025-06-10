//#include "http2-proxy-header.h"
//
//#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
//  {                                                                            \
//    (uint8_t *)NAME, (uint8_t *)VALUE,     sizeof(NAME) - 1,                   \
//    VALUELEN,        NGHTTP2_NV_FLAG_NONE,                                     \
//  }
//
//#define MAKE_NV2(NAME, VALUE)                                                  \
//  {                                                                            \
//    (uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,                 \
//    sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,                                   \
//  }
//
//#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))
//
//LPPER_IO_DATA UpdateIoCompletionPort(SOCKET sockfd, SOCKET peerSocket, IO_OPERATION ioOperation)
//{
//    LPPER_IO_DATA ioData = new PER_IO_DATA;
//
//    memset(&ioData->overlapped, '\0', sizeof(WSAOVERLAPPED));
//    ioData->clientSocket = sockfd;
//    ioData->serverSocket = peerSocket;
//    ioData->bytesRecv = 0;
//    ioData->bytesSend = 0;
//    ioData->ioOperation = ioOperation;
//
//    memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
//    memset(ioData->cSendBuffer, '\0', BUFFER_SIZE);
//    memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
//    memset(ioData->sSendBuffer, '\0', BUFFER_SIZE);
//
//    ioData->wsaClientRecvBuf.buf = ioData->cRecvBuffer;
//    ioData->wsaClientRecvBuf.len = sizeof(ioData->cRecvBuffer);
//    ioData->wsaClientSendBuf.buf = ioData->cSendBuffer;
//    ioData->wsaClientSendBuf.len = sizeof(ioData->cSendBuffer);
//    ioData->wsaServerRecvBuf.buf = ioData->sRecvBuffer;
//    ioData->wsaServerRecvBuf.len = sizeof(ioData->sRecvBuffer);
//    ioData->wsaServerSendBuf.buf = ioData->sSendBuffer;
//    ioData->wsaServerSendBuf.len = sizeof(ioData->sSendBuffer);
//
//    ioData->clientSSL = NULL;
//    ioData->clientCTX = NULL;
//    ioData->targetSSL = NULL;
//
//    ioData->crBio = NULL;
//    ioData->cwBio = NULL;
//    ioData->srBio = NULL;
//    ioData->swBio = NULL;
//
//    ioData->client_session_data = NULL;
//    ioData->server_session_data = NULL;
//
//    if (CreateIoCompletionPort((HANDLE)sockfd, g_completionPort, (ULONG_PTR)ioData, 0) == NULL)
//    {
//        printf("[-]CreateIoCompletionPort failed: %d\n", GetLastError());
//        delete ioData;
//        return NULL;
//    }
//
//    return ioData;
//}
//
//// adding SNI functionality to retrieve the host name from client hello
//int ServerNameCallback(SSL* ssl, int* ad, LPPER_IO_DATA ioData)
//{
//    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
//    if (servername)
//    {
//        printf("[+]SNI: %s\n", servername);
//        ioData->hostname = servername;
//
//        // Generate key for new certificate
//        ioData->pkey = EVP_PKEY_new();
//        RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
//        EVP_PKEY_assign_RSA(ioData->pkey, rsa);
//
//        // Generate new certificate
//        ioData->clientCert = create_certificate(rootCACert, rootCAKey, ioData->pkey, ioData->hostname);
//
//        // Assign new certificate and private key to SSL context
//        SSL_use_certificate(ssl, ioData->clientCert);
//        SSL_use_PrivateKey(ssl, ioData->pkey);
//    }
//    else
//    {
//        printf("[-]No SNI\n");
//    }
//    return SSL_TLSEXT_ERR_OK;
//}

//http2_client_stream_data* create_http2_client_stream_data(const char* uri,
//    struct http_parser_url* u) {
//    size_t extra = 7;
//    http2_client_stream_data* stream_data = new http2_client_stream_data();
//    if (stream_data)
//    {
//        stream_data->uri = uri;
//        stream_data->u = u;
//        stream_data->stream_id = -1;
//        stream_data->isBodyRecv = FALSE;
//
//        stream_data->authoritylen = u->field_data[UF_HOST].len;
//        stream_data->authority = (char*)malloc(stream_data->authoritylen + extra);
//        memcpy(stream_data->authority, &uri[u->field_data[UF_HOST].off],
//            u->field_data[UF_HOST].len);
//
//        if (u->field_set & (1 << UF_PORT))
//        {
//            stream_data->authoritylen +=
//                (size_t)snprintf(stream_data->authority + u->field_data[UF_HOST].len,
//                    extra, ":%u", u->port);
//        }
//
//        /* If we don't have path in URI, we use "/" as path. */
//        stream_data->pathlen = 1;
//        if (u->field_set & (1 << UF_PATH))
//        {
//            stream_data->pathlen = u->field_data[UF_PATH].len;
//        }
//        if (u->field_set & (1 << UF_QUERY))
//        {
//            /* +1 for '?' character */
//            stream_data->pathlen += (size_t)(u->field_data[UF_QUERY].len + 1);
//        }
//
//        stream_data->path = (char*)malloc(stream_data->pathlen);
//        if (u->field_set & (1 << UF_PATH))
//        {
//            memcpy(stream_data->path, &uri[u->field_data[UF_PATH].off],
//                u->field_data[UF_PATH].len);
//        }
//        else
//        {
//            stream_data->path[0] = '/';
//        }
//        if (u->field_set & (1 << UF_QUERY))
//        {
//            stream_data->path[stream_data->pathlen - u->field_data[UF_QUERY].len - 1] =
//                '?';
//            memcpy(stream_data->path + stream_data->pathlen -
//                u->field_data[UF_QUERY].len,
//                &uri[u->field_data[UF_QUERY].off], u->field_data[UF_QUERY].len);
//        }
//    }
//    return stream_data;
//}
//
//void delete_http2_client_stream_data(http2_client_stream_data* stream_data) {
//    free(stream_data->path);
//    free(stream_data->authority);
//    free(stream_data);
//    for (auto& nv : stream_data->headers) {
//        free(nv.name);
//        free(nv.value);
//    }
//}
//
///* Initializes |session_data| */
//http2_client_session_data* create_http2_client_session_data() {
//    http2_client_session_data* session_data = new http2_client_session_data();
//    return session_data;
//}
//
// void delete_http2_client_session_data(http2_client_session_data* session_data) {
//    nghttp2_session_del(session_data->session);
//    session_data->session = NULL;
//    if (session_data->stream_data) {
//        delete_http2_client_stream_data(session_data->stream_data);
//        session_data->stream_data = NULL;
//    }
//    free(session_data);
//}
//
///* Serialize the frame and send (or buffer) the data. */
//int client_session_send(http2_client_session_data* session_data) {
//    int rv;
//
//    printf("[=]client session send callback\n");
//
//    rv = nghttp2_session_send(session_data->session);
//    if (rv != 0) {
//        printf("Fatal error: %s\n", nghttp2_strerror(rv));
//        return -1;
//    }
//    return 0;
//}
//
//
//void print_header(FILE* f, const uint8_t* name, size_t namelen,
//    const uint8_t* value, size_t valuelen) {
//    fwrite(name, 1, namelen, f);
//    fprintf(f, ": ");
//    fwrite(value, 1, valuelen, f);
//    fprintf(f, "\n");
//}
//
///* Print HTTP headers to |f|. Please note that this function does not
//   take into account that header name and value are sequence of
//   octets, therefore they may contain non-printable characters. */
//void print_headers(FILE* f, nghttp2_nv* nva, size_t nvlen) {
//    size_t i;
//    for (i = 0; i < nvlen; ++i) {
//        print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
//    }
//    fprintf(f, "\n");
//}
//
///* nghttp2_send_callback2. Here we transmit the |data|, |length|
//   bytes, to the network. */
//nghttp2_ssize client_send_callback(nghttp2_session* session,
//    const uint8_t* data, size_t length,
//    int flags, void* user_data) {
//    int bio_read, ssl_write;
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    char buffer[BUFFER_SIZE] = { 0 };
//    (void)session;
//    (void)flags;
//
//    printf("[=]client send callback\n");
//
//    ssl_write = SSL_write(ioData->targetSSL, data, length);
//    if (ssl_write > 0)
//    {
//        printf("[+]ssl_write server cb: %d\n", ssl_write);
//        bio_read = BIO_read(ioData->swBio, buffer, BUFFER_SIZE);
//
//        if (bio_read > 0)
//        {
//            printf("[+]bio_read server cb: %d\n", bio_read);
//            memcpy(ioData->sSendBuffer, buffer, bio_read);
//
//            ioData->ioOperation = CLIENT_IO;
//            ioData->wsaServerSendBuf.len = bio_read;
//
//            if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
//            {
//                int error = WSAGetLastError();
//                if (error != WSA_IO_PENDING)
//                {
//                    printf("Failed to send response: %d\n", error);
//                    closesocket(ioData->serverSocket);
//                    delete ioData;
//                    return 0;
//                }
//            }
//            else
//            {
//                printf("[+]WSASend server cb: %d bytes\n", ioData->bytesSend);
//            }
//        }
//    }
//
//    return (nghttp2_ssize)length;
//}
//
///* nghttp2_on_header_callback: Called when nghttp2 library emits
//   single header name/value pair. */
//int client_on_header_callback(nghttp2_session* session,
//    const nghttp2_frame* frame, const uint8_t* name,
//    size_t namelen, const uint8_t* value,
//    size_t valuelen, uint8_t flags, void* user_data) {
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    (void)session;
//    (void)flags;
//
//    printf("[=]client header callback\n");
//
//    switch (frame->hd.type) {
//    case NGHTTP2_HEADERS:
//        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
//            ioData->client_session_data->stream_data->stream_id == frame->hd.stream_id) {
//            /* Print response headers for the initiated request. */
//            print_header(stderr, name, namelen, value, valuelen);
//            int32_t stream_id = frame->hd.stream_id;
//
//            nghttp2_nv nv;
//            nv.name = (uint8_t*)strndup((const char*)name, namelen);
//            nv.value = (uint8_t*)strndup((const char*)value, valuelen);
//            nv.namelen = namelen;
//            nv.valuelen = valuelen;
//            nv.flags = NGHTTP2_NV_FLAG_NONE;
//
//            //printf("[+] Pushing header to client stream_data %s:%s\n", name, value);
//            ioData->client_session_data->stream_data->headers.push_back(nv);
//
//            break;
//        }
//    }
//    return 0;
//}
//
///* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
//   started to receive header block. */
//int client_on_begin_headers_callback(nghttp2_session* session,
//    const nghttp2_frame* frame,
//    void* user_data) {
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    (void)session;
//
//    printf("[=]client begin headers callback\n");
//
//    switch (frame->hd.type) {
//    case NGHTTP2_HEADERS:
//        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
//            ioData->client_session_data->stream_data->stream_id == frame->hd.stream_id) {
//            fprintf(stderr, "[+]Response headers for stream ID=%d:\n",
//                frame->hd.stream_id);
//        }
//        break;
//    }
//    return 0;
//}
//
///* nghttp2_on_frame_recv_callback: Called when nghttp2 library
//   received a complete frame from the remote peer. */
//int client_on_frame_recv_callback(nghttp2_session* session,
//    const nghttp2_frame* frame, void* user_data) {
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    (void)session;
//
//    printf("[=]client frame recv callback\n");
//
//    switch (frame->hd.type) {
//    case NGHTTP2_HEADERS:
//        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
//            ioData->client_session_data->stream_data->stream_id == frame->hd.stream_id) {
//            fprintf(stderr, "[+]All headers received\n");
//        }
//        break;
//    case NGHTTP2_DATA:
//        if (ioData->client_session_data->stream_data->stream_id == frame->hd.stream_id) {
//            fprintf(stderr, "[+]All data received\n");
//            int ret = server_send_response(ioData->server_session_data->session, frame->hd.stream_id, ioData);
//        }
//        break;
//    }
//
//
//    return 0;
//}
//
///* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
//   received from the remote peer. In this implementation, if the frame
//   is meant to the stream we initiated, print the received data in
//   stdout, so that the user can redirect its output to the file
//   easily. */
//int client_on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags,
//    int32_t stream_id, const uint8_t* data,
//    size_t len, void* user_data) {
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    (void)session;
//    (void)flags;
//
//    printf("[=]client on data chunk recv callback\n");
//
//    if (ioData->client_session_data->stream_data->stream_id == stream_id) {
//        //fwrite(data, 1, len, stdout);
//        ioData->client_session_data->stream_data->isBodyRecv = TRUE;
//        ioData->client_session_data->stream_data->body.append(reinterpret_cast<const char*>(data), len);
//
//        //int ret = server_send_response(ioData->server_session_data->session, stream_id, ioData);
//        //printf("[+]copied response body %d bytes - \n%s\n", ioData->client_session_data->stream_data->body.size(), ioData->client_session_data->stream_data->body.c_str());
//    }
//    return 0;
//}
//
///* nghttp2_on_stream_close_callback: Called when a stream is about to
//   closed. This example program only deals with 1 HTTP request (1
//   stream), if it is closed, we send GOAWAY and tear down the
//   session */
//int client_on_stream_close_callback(nghttp2_session* session, int32_t stream_id,
//    uint32_t error_code, void* user_data) {
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    int rv;
//
//    //int ret = server_send_response(ioData->server_session_data->session, stream_id, ioData);
//
//    printf("[=]client stream close callback\n");
//
//    if (ioData->client_session_data->stream_data->stream_id == stream_id) {
//        fprintf(stderr, "Stream %d closed with error_code=%u\n", stream_id,
//            error_code);
//        rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
//        if (rv != 0) {
//            return NGHTTP2_ERR_CALLBACK_FAILURE;
//        }
//    }
//    printf("[=]client stream close callback\n");
//    return 0;
//}
//
//// forward request to client
//void client_submit_request(http2_client_session_data* session_data, vector<nghttp2_nv> hdrs)
//{
//    int32_t stream_id;
//    http2_client_stream_data* stream_data = session_data->stream_data;
//
//    printf("[=]client submit request\n");
//
//    print_headers(stderr, hdrs.data(), (int)hdrs.size());
//
//    stream_id = nghttp2_submit_request2(session_data->session,
//        NULL,
//        hdrs.data(),
//        (int)hdrs.size(),
//        NULL,
//        stream_data);
//
//    if (stream_id < 0) {
//        printf("[-]Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
//    }
//    else
//    {
//        printf("[+]HTTP request submitted - stream ID: %d\n", stream_id);
//    }
//    stream_data->stream_id = stream_id;
//
//    printf("calling client session send callback\n");
//    if (client_session_send(session_data) != 0)
//    {
//        delete_http2_client_session_data(session_data);
//        return;
//    }
//
//    return;
//}
//
///* Send HTTP/2 client connection header, which includes 24 bytes
//   magic octets and SETTINGS frame */
//static int send_server_connection_header(http2_server_session_data* session_data) {
//    nghttp2_settings_entry iv[1] = {
//      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100} };
//    int rv;
//
//    printf("[=]server connection header\n");
//
//    rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
//    if (rv != 0) {
//        printf("[-]Fatal error: %s\n", nghttp2_strerror(rv));
//        return -1;
//    }
//    return 0;
//}
//
//
//static void server_add_stream(http2_server_session_data* session_data,
//    http2_server_stream_data* stream_data) {
//    stream_data->next = session_data->root.next;
//    session_data->root.next = stream_data;
//    stream_data->prev = &session_data->root;
//
//    printf("[=]server add stream\n");
//
//    if (stream_data->next) {
//        stream_data->next->prev = stream_data;
//    }
//}
//
//static void server_remove_stream(http2_server_session_data* session_data,
//    http2_server_stream_data* stream_data) {
//    (void)session_data;
//
//    stream_data->prev->next = stream_data->next;
//    if (stream_data->next) {
//        stream_data->next->prev = stream_data->prev;
//    }
//}
//
//static http2_server_stream_data*
//create_http2_server_stream_data(http2_server_session_data* session_data, int32_t stream_id) {
//    http2_server_stream_data* stream_data;
//    stream_data = new http2_server_stream_data();
//    stream_data->stream_id = stream_id;
//    stream_data->fd = -1;
//
//    server_add_stream(session_data, stream_data);
//    return stream_data;
//}
//
//static void delete_http2_server_stream_data(http2_server_stream_data* stream_data) {
//    if (stream_data->fd != -1) {
//        close(stream_data->fd);
//    }
//    for (auto& nv : stream_data->headers) {
//        free(nv.name);
//        free(nv.value);
//    }
//    free(stream_data->request_path);
//    free(stream_data);
//}
//
//static http2_server_session_data* create_http2_server_session_data(SSL_CTX* ssl_ctx,
//    int fd,
//    struct sockaddr* addr,
//    int addrlen) {
//    int rv;
//    http2_server_session_data* session_data;
//    SSL* ssl;
//    char host[NI_MAXHOST];
//    int val = 1;
//
//    ssl = SSL_new(ssl_ctx);
//    if (!ssl) {
//        printf("[-]SSL_new failed\n");
//    }
//    session_data = (http2_server_session_data*)malloc(sizeof(http2_server_session_data));
//    if (!session_data) {
//        printf("[-]malloc failed\n");
//        return NULL;
//    }
//    else {
//        memset(session_data, 0, sizeof(http2_server_session_data));
//        session_data->ssl_ctx = ssl_ctx;
//        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&val, sizeof(val));
//    }
//
//    return session_data;
//}
//
//static void delete_http2_server_session_data(http2_server_session_data* session_data, SSL* ssl) {
//    http2_server_stream_data* stream_data;
//    fprintf(stderr, "%s disconnected\n", session_data->client_addr);
//    if (ssl) {
//        SSL_shutdown(ssl);
//    }
//    nghttp2_session_del(session_data->session);
//    for (stream_data = session_data->root.next; stream_data;) {
//        http2_server_stream_data* next = stream_data->next;
//        delete_http2_server_stream_data(stream_data);
//        stream_data = next;
//    }
//    free(session_data->client_addr);
//    free(session_data);
//}
//
///* Serialize the frame and send (or buffer) the data to
//   bufferevent. */
//static int server_session_send(http2_server_session_data* session_data) {
//    int rv;
//    printf("[=]server session send\n");
//    rv = nghttp2_session_send(session_data->session);
//    printf("[=]nghttp2 session send - %d\n", rv);
//    if (rv != 0) {
//        printf("Fatal error: %s\n", nghttp2_strerror(rv));
//        return -1;
//    }
//    return 0;
//}
//
///* Read the data in the bufferevent and feed them into nghttp2 library
//   function. Invocation of nghttp2_session_mem_recv2() may make
//   additional pending frames, so call session_send() at the end of the
//   function. */
//static int server_session_recv(PER_IO_DATA* ioData) {
//    nghttp2_ssize readlen;
//    DWORD flags = 0;
//    int bio_write, ssl_read, nghttp2_read;
//
//    printf("[=] server session recv\n");
//
//    if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
//    {
//        int error = WSAGetLastError();
//        printf("[-]WSARecv server IO pending. ID - %d\n", ioData->key);
//        if (error != WSA_IO_PENDING)
//        {
//            printf("[-]WSARecv() failed - %d. ID - %d\n", error, ioData->key);
//            closesocket(ioData->serverSocket);
//            delete ioData;
//            return 0;
//        }
//    }
//    else
//    {
//        printf("[+]WSARecv() server - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
//    }
//
//    if (strlen(ioData->sRecvBuffer) > 0)
//    {
//        bio_write = BIO_write(ioData->srBio, ioData->sRecvBuffer, ioData->bytesRecv);
//        if (bio_write > 0)
//        {
//            printf("[+]bio_write server: %d. ID - %d\n", bio_write, ioData->key);
//
//            ssl_read = SSL_read(ioData->targetSSL, ioData->sRecvBuffer, BUFFER_SIZE);
//
//            if (ssl_read > 0)
//            {
//                printf("[+]ssl_read server: %d. ID - %d\n", ssl_read, ioData->key);
//                printf("%s\n", ioData->sRecvBuffer);
//                nghttp2_read = nghttp2_session_mem_recv2(ioData->server_session_data->session, (uint8_t*)ioData->sRecvBuffer, ssl_read);
//                if (nghttp2_read < 0) {
//                    printf("Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
//                    delete_http2_server_session_data(ioData->server_session_data, ioData->targetSSL);
//                    return 0;
//                }
//                memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
//                if (server_session_send(ioData->server_session_data) != 0) {
//                    printf("session_send 2\n");
//                    delete_http2_server_session_data(ioData->server_session_data, ioData->targetSSL);
//                    return 0;
//                }
//                while ((ssl_read = SSL_read(ioData->targetSSL, ioData->sRecvBuffer, BUFFER_SIZE)) > 0)
//                {
//                    printf("[+]ssl_read server: %d\n", ssl_read);
//                    printf("%s\n", ioData->sRecvBuffer);
//                    nghttp2_read = nghttp2_session_mem_recv2(ioData->server_session_data->session, (uint8_t*)ioData->sRecvBuffer, ssl_read);
//                    if (nghttp2_read < 0) {
//                        printf("Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
//                        delete_http2_server_session_data(ioData->server_session_data, ioData->targetSSL);
//                        break;
//                    }
//                    memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
//                    if (server_session_send(ioData->server_session_data) != 0) {
//                        printf("session_send 2\n");
//                        delete_http2_server_session_data(ioData->server_session_data, ioData->targetSSL);
//                        break;
//                    }
//                }
//            }
//        }
//    }
//
//    if (server_session_send(ioData->server_session_data) != 0) {
//        return -1;
//    }
//    return 0;
//}
//
//static nghttp2_ssize server_send_callback(nghttp2_session* session,
//    const uint8_t* data, size_t length,
//    int flags, void* user_data) {
//    int bio_read, ssl_write;
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    char buffer[BUFFER_SIZE] = { 0 };
//    (void)session;
//    (void)flags;
//
//    printf("[=]server send callback\n");
//
//    ssl_write = SSL_write(ioData->clientSSL, data, length);
//    if (ssl_write > 0)
//    {
//        printf("[+]ssl_write client: %d\n", ssl_write);
//        bio_read = BIO_read(ioData->cwBio, buffer, BUFFER_SIZE);
//        if (bio_read > 0)
//        {
//            ioData->clientRecvFlag = FALSE;
//            printf("[+]bio_read client: %d\n", bio_read);
//            memcpy(ioData->cSendBuffer, buffer, bio_read);
//
//            if (ioData->ioFlag)
//            {
//                ioData->ioOperation = SERVER_IO;
//            }
//
//            ioData->wsaClientSendBuf.len = bio_read;
//
//            if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
//            {
//                int error = WSAGetLastError();
//                if (error != WSA_IO_PENDING)
//                {
//                    printf("Failed to send response: %d\n", error);
//                    closesocket(ioData->clientSocket);
//                    delete ioData;
//                    return 0;
//                }
//            }
//            else
//            {
//                printf("[+]WSASend client: %d bytes\n", ioData->bytesSend);
//            }
//        }
//    }
//
//    return (nghttp2_ssize)length;
//}
//
///* Returns nonzero if the string |s| ends with the substring |sub| */
//static int ends_with(const char* s, const char* sub) {
//    size_t slen = strlen(s);
//    size_t sublen = strlen(sub);
//    if (slen < sublen) {
//        return 0;
//    }
//    return memcmp(s + slen - sublen, sub, sublen) == 0;
//}
//
///* Returns int value of hex string character |c| */
//static uint8_t hex_to_uint(uint8_t c) {
//    if ('0' <= c && c <= '9') {
//        return (uint8_t)(c - '0');
//    }
//    if ('A' <= c && c <= 'F') {
//        return (uint8_t)(c - 'A' + 10);
//    }
//    if ('a' <= c && c <= 'f') {
//        return (uint8_t)(c - 'a' + 10);
//    }
//    return 0;
//}
//
///* Decodes percent-encoded byte string |value| with length |valuelen|
//   and returns the decoded byte string in allocated buffer. The return
//   value is NULL terminated. The caller must free the returned
//   string. */
//static char* percent_decode(const uint8_t* value, size_t valuelen) {
//    char* res;
//
//    res = (char*)malloc(valuelen + 1);
//    if (valuelen > 3) {
//        size_t i, j;
//        for (i = 0, j = 0; i < valuelen - 2;) {
//            if (value[i] != '%' || !isxdigit(value[i + 1]) ||
//                !isxdigit(value[i + 2])) {
//                res[j++] = (char)value[i++];
//                continue;
//            }
//            res[j++] =
//                (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
//            i += 3;
//        }
//        memcpy(&res[j], &value[i], 2);
//        res[j + 2] = '\0';
//    }
//    else {
//        memcpy(res, value, valuelen);
//        res[valuelen] = '\0';
//    }
//    return res;
//}
//
//static nghttp2_ssize buffer_read_callback(nghttp2_session* session,
//    int32_t stream_id, uint8_t* buf,
//    size_t length, uint32_t* data_flags,
//    nghttp2_data_source* source,
//    void* user_data) {
//
//    printf("[=]buffer read callback\n");
//
//    buffer_source* src = (buffer_source*)source->ptr;
//    size_t remaining = src->length - src->offset;
//    size_t copylen = min(remaining, length);
//
//    if (copylen > 0) {
//        memcpy(buf, src->data + src->offset, copylen);
//        src->offset += copylen;
//    }
//
//    if (src->offset >= src->length) {
//        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
//    }
//
//    return (nghttp2_ssize)copylen;
//}
//
//// forward response to server
//static int server_send_response(nghttp2_session* session, int32_t stream_id, PER_IO_DATA* ioData) {
//    int rv;
//
//    printf("[=]server send response\n");
//
//    ioData->client_session_data->stream_data->isBodyRecv = FALSE;
//
//    /*print_headers(  stdout,
//                    ioData->client_session_data->stream_data->headers.data(),
//                    (int)ioData->client_session_data->stream_data->headers.size());
//
//    printf("[+]body size:%d\n", ioData->client_session_data->stream_data->body.size());*/
//
//    buffer_source* src = new buffer_source;
//    src->data = ioData->client_session_data->stream_data->body.data();
//    src->length = ioData->client_session_data->stream_data->body.size();
//    src->offset = 0;
//
//    nghttp2_data_provider2 data_prd;
//    data_prd.source.ptr = src;
//    data_prd.read_callback = buffer_read_callback;
//
//    rv = nghttp2_submit_headers(session,
//        NGHTTP2_FLAG_NONE,
//        stream_id,
//        NULL,
//        ioData->client_session_data->stream_data->headers.data(),
//        (size_t)ioData->client_session_data->stream_data->headers.size(),
//        NULL);
//
//    /*rv = nghttp2_submit_response2(session,
//                                  stream_id,
//                                  ioData->client_session_data->stream_data->headers.data(),
//                                  ioData->client_session_data->stream_data->headers.size(),
//                                  &data_prd);*/
//
//    if (rv != 0) {
//        printf("[-]Fatal error: %s\n", nghttp2_strerror(rv));
//        return -1;
//    }
//    else
//    {
//        printf("[+]Response headers forwarded to client - stream ID: %d. ID - %d\n", stream_id, ioData->key);
//    }
//
//    //delete src;
//    //ioData->client_session_data->stream_data->headers.clear();
//    //ioData->client_session_data->stream_data->body.clear();
//
//    if (server_session_send(ioData->server_session_data) != 0)
//    {
//        delete_http2_server_session_data(ioData->server_session_data, ioData->targetSSL);
//        return -1;
//    }
//
//    return 0;
//}
//
//#define MAKE_NV(NAME, VALUE)                                                   \
//  {                                                                            \
//    (uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,                 \
//    sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,                                   \
//  }
//
//static const char ERROR_HTML[] =
//"<html><head><title>404</title></head>"
//"<body><h1>404 Not Found</h1></body></html>";
//
//static int error_reply(nghttp2_session* session,
//    http2_server_stream_data* stream_data) {
//
//    printf("[=]error reply.\n");
//
//    static const size_t body_len = sizeof(ERROR_HTML) - 1;
//
//    //// Allocate and copy response body to stream_data
//    //stream_data->resp_body = (uint8_t*)malloc(body_len);
//    //if (!stream_data->resp_body) {
//    //    return nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
//    //        stream_data->stream_id,
//    //        NGHTTP2_INTERNAL_ERROR);
//    //}
//
//    //memcpy(stream_data->resp_body, ERROR_HTML, body_len);
//    //stream_data->resp_bodylen = body_len;
//    //stream_data->resp_body_offset = 0;
//
//    //nghttp2_nv hdrs[] = {
//    //    MAKE_NV(":status", "404"),
//    //    MAKE_NV("content-type", "text/html"),
//    //    MAKE_NV("content-length", "65")
//    //};
//
//    //// Define data source callback using nghttp2_data_provider2
//    //nghttp2_data_source_read_callback2 read_cb = [](nghttp2_session* session,
//    //    int32_t stream_id,
//    //    uint8_t* buf,
//    //    size_t length,
//    //    uint32_t* data_flags,
//    //    nghttp2_data_source* source,
//    //    void* user_data) -> long long {
//    //        http2_server_stream_data* sd = (http2_server_stream_data*)user_data;
//
//    //        size_t remaining = sd->resp_bodylen - sd->resp_body_offset;
//    //        size_t to_copy = min(length, remaining);
//
//    //        if (to_copy > 0) {
//    //            memcpy(buf, sd->resp_body + sd->resp_body_offset, to_copy);
//    //            sd->resp_body_offset += to_copy;
//    //        }
//
//    //        if (sd->resp_body_offset == sd->resp_bodylen) {
//    //            *data_flags = NGHTTP2_DATA_FLAG_EOF;
//    //        }
//
//    //        return (long long)to_copy;
//    //    };
//
//    //nghttp2_data_provider2 data_prd;
//    //data_prd.read_callback = read_cb;
//    //data_prd.source.ptr = nullptr;
//
//    //int rv = nghttp2_submit_response2(session,
//    //    stream_data->stream_id,
//    //    hdrs, ARRLEN(hdrs),
//    //    &data_prd); // <- this is user_data for read_cb
//
//    //if (rv != 0) {
//    //    free(stream_data->resp_body);
//    //    stream_data->resp_body = nullptr;
//    //    return -1;
//    //}
//    return 0;
//}
//
//static int server_on_header_callback(nghttp2_session* session,
//    const nghttp2_frame* frame, const uint8_t* name,
//    size_t namelen, const uint8_t* value,
//    size_t valuelen, uint8_t flags, void* user_data) {
//
//    const char PATH[] = ":path";
//    (void)flags;
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//
//    if (!session || !frame || !user_data) {
//        fprintf(stderr, "[-]Invalid arguments to header callback\n");
//        return NGHTTP2_ERR_CALLBACK_FAILURE;
//    }
//
//    //printf("[=]server header callback\n");
//
//    if (frame->hd.type == NGHTTP2_HEADERS &&
//        frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
//
//        //print_header(stderr, name, namelen, value, valuelen);
//
//        http2_server_stream_data* stream_data = (http2_server_stream_data*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
//
//        if (!stream_data) {
//            fprintf(stderr, "[-]stream_data is NULL for stream_id %d\n", frame->hd.stream_id);
//            return 0;
//        }
//
//        nghttp2_nv nv;
//        nv.name = (uint8_t*)strndup((const char*)name, namelen);
//        nv.value = (uint8_t*)strndup((const char*)value, valuelen);
//        nv.namelen = namelen;
//        nv.valuelen = valuelen;
//        nv.flags = NGHTTP2_NV_FLAG_NONE;
//        if (stream_data) {
//            stream_data->headers.push_back(nv);
//        }
//        else {
//            printf("[-] stream_data is NULL! Should never happen.\n");
//        }
//        // Handle path separately for query-stripping
//        if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
//            size_t j;
//            for (j = 0; j < valuelen && value[j] != '?'; ++j)
//                ;
//            stream_data->request_path = percent_decode(value, j);
//        }
//    }
//
//    return 0;
//}
//
//
//static int server_on_begin_headers_callback(nghttp2_session* session,
//    const nghttp2_frame* frame,
//    void* user_data) {
//    //http2_server_session_data* session_data = (http2_server_session_data*)user_data;
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    http2_server_stream_data* stream_data;
//
//    printf("[=]server begin headers cb\n");
//
//    if (frame->hd.type != NGHTTP2_HEADERS ||
//        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
//        return 0;
//    }
//    stream_data = create_http2_server_stream_data(ioData->server_session_data, frame->hd.stream_id);
//    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, stream_data);
//
//    return 0;
//}
//
///* Minimum check for directory traversal. Returns nonzero if it is
//   safe. */
//static int check_path(const char* path) {
//    return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
//        strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
//        !ends_with(path, "/..") && !ends_with(path, "/.");
//}
//
//static int server_on_request_recv(nghttp2_session* session,
//    PER_IO_DATA* ioData,
//    http2_server_stream_data* stream_data) {
//    int fd;
//    char* rel_path;
//
//    printf("[=]server on request recv\n");
//
//    client_submit_request(ioData->client_session_data, stream_data->headers);
//
//    return 0;
//}
//
//static int server_on_frame_recv_callback(nghttp2_session* session,
//    const nghttp2_frame* frame, void* user_data) {
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    http2_server_stream_data* stream_data;
//
//    printf("[=]server on frame recv cb\n");
//
//    switch (frame->hd.type) {
//    case NGHTTP2_DATA:
//    case NGHTTP2_HEADERS:
//        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
//            stream_data =
//                (http2_server_stream_data*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
//            if (!stream_data) {
//                return 0;
//            }
//            printf("[=]server full body received for stream_id %d\n", frame->hd.stream_id);
//            printf("[+]body: %s\n", stream_data->body.c_str());
//            ioData->server_session_data->last_stream_id = stream_data->stream_id;
//            return server_on_request_recv(session, ioData, stream_data);
//        }
//        break;
//    default:
//        break;
//    }
//    return 0;
//}
//
//static int server_on_data_chunk_recv_callback(nghttp2_session* session,
//    uint8_t flags, int32_t stream_id,
//    const uint8_t* data, size_t len,
//    void* user_data) {
//
//    printf("[=]on data chunk recv cb\n");
//
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    http2_server_stream_data* stream_data =
//        (http2_server_stream_data*)nghttp2_session_get_stream_user_data(session, stream_id);
//
//    if (!stream_data) {
//        fprintf(stderr, "[-] stream_data is NULL in data chunk callback for stream %d\n", stream_id);
//        return NGHTTP2_ERR_CALLBACK_FAILURE;
//    }
//
//    printf("[=] server data chunk received: %zu bytes for stream_id %d\n", len, stream_id);
//
//    stream_data->body.append(reinterpret_cast<const char*>(data), len);
//
//    return 0;
//}
//
//static int server_on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data)
//{
//    PER_IO_DATA* ioData = (PER_IO_DATA*)user_data;
//    http2_server_stream_data* stream_data;
//    (void)error_code;
//
//    printf("[=]server on stream close callback\n");
//
//    stream_data = (http2_server_stream_data*)nghttp2_session_get_stream_user_data(session, stream_id);
//    if (!stream_data) {
//        return 0;
//    }
//    ioData->server_session_data->last_stream_id = -1;
//    server_remove_stream(ioData->server_session_data, stream_data);
//    delete_http2_server_stream_data(stream_data);
//    return 0;
//}