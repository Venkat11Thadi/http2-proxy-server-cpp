#include "http2-proxy-header.h"
#include "http_parser.h"

using namespace std;

LPPER_IO_DATA UpdateIoCompletionPort(SOCKET socket, IO_OPERATION ioOperation);
static DWORD WINAPI WorkerThread(LPVOID lparameter);
VOID StartServer(VOID);

int main()
{
	StartServer();
	return 0;
}

VOID StartServer()
{
	InitializeWinsock();
	InitializeOpenSSL();

	FILE* rootCACertFile = fopen("C:\\Users\\USER\\Desktop\\certs\\rootCA.crt", "r");
	if (!rootCACertFile)
	{
		printf("[-]Cannot open rootCA.crt\n");
		WSACleanup();
		return;
	}
	rootCACert = PEM_read_X509(rootCACertFile, NULL, NULL, NULL);
	if (!rootCACert)
	{
		printf("[-]Cannot read rootCA.crt\n");
		WSACleanup();
		return;
	}
	fclose(rootCACertFile);

	FILE* rootCAKeyFile = fopen("C:\\Users\\USER\\Desktop\\certs\\rootCA.key", "r");
	if (!rootCAKeyFile)
	{
		printf("[-]Cannot open rootCA.key\n");
		WSACleanup();
		return;
	}
	rootCAKey = PEM_read_PrivateKey(rootCAKeyFile, NULL, NULL, NULL);
	if (!rootCAKey)
	{
		printf("[-]Cannot read rootCA.key\n");
		WSACleanup();
		return;
	}
	fclose(rootCAKeyFile);

	g_completionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (!g_completionPort)
	{
		printf("[-]Cannot create IO completion port\n");
		WSACleanup();
		return;
	}
	else
	{
		printf("[+]IO completion port created.\n");
	}

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	for (DWORD i = 0; i < sysInfo.dwNumberOfProcessors; i++)
	{
		HANDLE thread = CreateThread(NULL, 0, WorkerThread, g_completionPort, 0, NULL);
		if (thread == NULL)
		{
			printf("[-]Failed to create worker thread.\n");
			WSACleanup();
			return;
		}
		CloseHandle(thread);
	}

	SOCKET sockfd = StartListen(PORT);
	if (sockfd == INVALID_SOCKET)
	{
		printf("[-]Invalid socket.\n");
		return;
	}

	while (TRUE)
	{
		SOCKET clientSocket = WSAAccept(sockfd, NULL, NULL, NULL, 0);
		if (clientSocket == INVALID_SOCKET)
		{
			printf("[-]WSAAccept failed\n");
			continue;
		}
		else
		{
			printf("[+]Client accepted.\n");
		}
		LPPER_IO_DATA ioData = UpdateIoCompletionPort(clientSocket, INVALID_SOCKET, CLIENT_ACCEPT);
		if (ioData == NULL)
		{
			printf("[-]UpdateIoCompletionPort failed - %d\n", WSAGetLastError());
			closesocket(clientSocket);
			continue;
		}
		else
		{
			printf("[+]UpdateIoCompletionPort done.\n");
		}

		DWORD flags = 0;
		if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
		{
			int error = WSAGetLastError();
			if (error != WSA_IO_PENDING)
			{
				printf("[-]WSARecv failed: %d\n", error);
				closesocket(clientSocket);
				delete ioData;
				continue;
			}
		}
		else
		{
			printf("[+]WSARecv - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
		}
	}
}

static void initialize_client_nghttp2_session(PER_IO_DATA* ioData) {
	nghttp2_session_callbacks* callbacks;

	nghttp2_session_callbacks_new(&callbacks);

	nghttp2_session_callbacks_set_send_callback2(callbacks, client_send_callback);

	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
		client_on_frame_recv_callback);

	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		callbacks, client_on_data_chunk_recv_callback);

	nghttp2_session_callbacks_set_on_stream_close_callback(
		callbacks, client_on_stream_close_callback);

	nghttp2_session_callbacks_set_on_header_callback(callbacks,
		client_on_header_callback);

	nghttp2_session_callbacks_set_on_begin_headers_callback(
		callbacks, client_on_begin_headers_callback);

	nghttp2_session_client_new(&ioData->client_session_data->session, callbacks, ioData);

	nghttp2_session_callbacks_del(callbacks);
}

static void initialize_server_nghttp2_session(PER_IO_DATA* ioData) {
	nghttp2_session_callbacks* callbacks;

	nghttp2_session_callbacks_new(&callbacks);

	nghttp2_session_callbacks_set_send_callback2(callbacks, server_send_callback);

	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
		server_on_frame_recv_callback);

	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		callbacks, server_on_data_chunk_recv_callback);

	nghttp2_session_callbacks_set_on_stream_close_callback(
		callbacks, server_on_stream_close_callback);

	nghttp2_session_callbacks_set_on_header_callback(callbacks,
		server_on_header_callback);

	nghttp2_session_callbacks_set_on_begin_headers_callback(
		callbacks, server_on_begin_headers_callback);

	nghttp2_session_server_new(&ioData->server_session_data->session, callbacks, ioData);

	nghttp2_session_callbacks_del(callbacks);
}

static DWORD WINAPI WorkerThread(LPVOID lparameter)
{
	HANDLE completionPort = (HANDLE)lparameter;
	LPPER_IO_DATA socketData = NULL;
	LPWSAOVERLAPPED overlapped = NULL;
	DWORD flags = 0;
	DWORD bytesTransferred = 0;

	while (TRUE)
	{
		BOOL result = GetQueuedCompletionStatus(completionPort,
			&bytesTransferred,
			(PDWORD_PTR)&socketData,
			(LPOVERLAPPED*)&overlapped,
			INFINITE);

		LPPER_IO_DATA ioData = (LPPER_IO_DATA)overlapped;
		if (!result)
		{
			printf("[-]GetQueuedCompletionStatus failed: %d\n", GetLastError());
		}

		if (ioData == NULL)
		{
			printf("[-]IO_DATA NULL\n");
			return 0;
		}

		if (!result || bytesTransferred == 0)
		{
			printf("[=]Connection closed.\n");
			if (ioData)
			{
				closesocket(ioData->clientSocket);
				ioData->clientSocket = INVALID_SOCKET;
				delete ioData;
			}
			return 0;
		}

		switch (ioData->ioOperation)
		{
		case CLIENT_ACCEPT:
		{
			printf("[=]ACCEPT\n");
			ioData->bytesRecv = bytesTransferred;

			int port = 0;
			string request(ioData->cRecvBuffer, ioData->bytesRecv);

			if (strncmp(ioData->cRecvBuffer, "CONNECT", 7) == 0)
			{

				string hostname;
				if (!ParseConnectRequest(request, hostname, port))
				{
					printf("[-]Invalid CONNECT request\n");
					closesocket(ioData->clientSocket);
					delete ioData;
					break;
				}

				printf("[=]connect request - %s:%d\n", hostname.c_str(), port);

				if (!hostname.empty())
				{
					ioData->hostname = hostname;
					ioData->serverSocket = ConnectToTarget(hostname, port);
					printf("[+]Connected to server - %s, on port - %d. ID - %d\n", hostname.c_str(), port, ioData->key);

					if (ioData->serverSocket != INVALID_SOCKET)
					{
						if (CreateIoCompletionPort((HANDLE)ioData->serverSocket, completionPort, NULL, 0) == NULL)
						{
							printf("[-]CreateIoCompletionPort for server failed. ID - %d\n", ioData->key);
							closesocket(ioData->serverSocket);
							ioData->serverSocket = INVALID_SOCKET;
							closesocket(ioData->clientSocket);
							ioData->clientSocket = INVALID_SOCKET;
							delete ioData;
							break;
						}
						else if (detailLog)
						{
							printf("[+]Updated Io completion port. ID - %d\n", ioData->key);
						}
					}

					// using BIO memory buffers to transfer data between sockets
					ioData->crBio = BIO_new(BIO_s_mem());
					ioData->cwBio = BIO_new(BIO_s_mem());
					ioData->srBio = BIO_new(BIO_s_mem());
					ioData->swBio = BIO_new(BIO_s_mem());
					if (!ioData->crBio || !ioData->cwBio || !ioData->srBio || !ioData->swBio)
					{
						printf("[-]BIO_new failed. ID - %d\n", ioData->key);
						closesocket(ioData->clientSocket);
						break;
					}
					else
					{
						// set the memory BIOs to non-blocking mode
						BIO_set_nbio(ioData->crBio, 1);
						BIO_set_nbio(ioData->cwBio, 1);
						BIO_set_nbio(ioData->srBio, 1);
						BIO_set_nbio(ioData->swBio, 1);
					}

					SSL_CTX* targetCTX = client_SSL_CTX();
					ioData->targetSSL = SSL_new(targetCTX);
					if (!SSL_set_tlsext_host_name(ioData->targetSSL, ioData->hostname.c_str()))
					{
						printf("[-]SSL_set_tlsext_host_name() failed. ID - %d\n", ioData->key);
						ERR_print_errors_fp(stderr);
						break;
					}

					//const CHAR* uri = "https://www.google.com";
					struct http_parser_url u;
					uint16_t port;
					CHAR* host;
					INT rv;

					std::string uri = ExtractHostWithPort(request);

					/* Parse the |uri| and stores its components in |u| */
					rv = http_parser_parse_url(uri.c_str(), strlen(uri.c_str()), 1, &u);
					if (rv != 0) {
						printf("Could not parse URI %s", uri.c_str());
					}
					host = _strdup(&uri.c_str()[u.field_data[UF_HOST].off]);
					if (!(u.field_set & (1 << UF_PORT))) {
						port = 443;
					}
					else {
						port = u.port;
					}
					printf("[+]Parsed URI: %s\n", uri.c_str());

					ioData->client_session_data = create_http2_client_session_data();
					ioData->client_session_data->stream_data = create_http2_client_stream_data(uri.c_str(), &u);

					// to act as CLIENT
					SSL_set_connect_state(ioData->targetSSL);
					SSL_CTX_set_verify(targetCTX, SSL_VERIFY_NONE, NULL);
					SSL_set_bio(ioData->targetSSL, ioData->srBio, ioData->swBio);

					memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);

					ioData->ioOperation = SERVER_SSL_HANDSHAKE;
					char response[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
					memcpy(ioData->wsaClientSendBuf.buf, response, sizeof(response));
					ioData->wsaClientSendBuf.len = sizeof(response);
					if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
					{
						int error = WSAGetLastError();
						if (error != WSA_IO_PENDING)
						{
							printf("[-]WSASend() failed: %d\n", error);
							closesocket(ioData->clientSocket);
							closesocket(ioData->serverSocket);
							delete ioData;
							break;
						}
					}
					else
					{
						printf("[+]Connection established with client. ID - %d\n", ioData->key);
					}
				}
			}
			else
			{
				printf("Request: %s\n", request.c_str());
			}

			break;
		}

		case SERVER_SSL_HANDSHAKE:
		{
			if (strlen(ioData->sRecvBuffer) > 0)
			{
				int bio_write = BIO_write(ioData->srBio, ioData->sRecvBuffer, bytesTransferred);
				if (bio_write > 0)
				{
					printf("[+]BIO_write() server - %d bytes. ID - %d\n", bio_write, ioData->key);
				}
				memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
			}

			// SSL handshake with server
			if (!SSL_is_init_finished(ioData->targetSSL))
			{
				char Buf[BUFFER_SIZE] = {};
				int bio_read = 0, ret_server, status;

				ret_server = SSL_do_handshake(ioData->targetSSL);

				if (ret_server == 1)
				{
					// SSL handshake with client
					ioData->ioOperation = CLIENT_SSL_HANDSHAKE;

					printf("[+]SSL handshake done with server\n");

					// check if alpn is negotiated after handshake
					const unsigned char* alpn = NULL;
					unsigned int alpnlen = 0;

					if (alpn == NULL) {
						SSL_get0_alpn_selected(ioData->targetSSL, &alpn, &alpnlen);
					}

					if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
						fprintf(stderr, "[-]h2 is not negotiated\n");
						break;
					}
					printf("[+]ALPN negotiated with server\n");

					initialize_client_nghttp2_session(ioData);

					int val = 1;
					setsockopt(ioData->serverSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&val, sizeof(val));

					// send client connection header
					nghttp2_settings_entry iv[1] = { {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100} };
					int rv;

					// client 24 bytes magic string will be sent by nghttp2 library
					rv = nghttp2_submit_settings(ioData->client_session_data->session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
					if (rv != 0) {
						printf("[-]Could not submit SETTINGS: %s", nghttp2_strerror(rv));
						break;
					}
					else
					{
						printf("[+]Submitted settings\n");
					}

					// Extract certificate of Server
					ioData->targetCert = SSL_get_peer_certificate(ioData->targetSSL);
					if (!ioData->targetCert)
					{
						printf("[-]Cert of server not extracted. ID - %d\n", ioData->key);
						SSL_shutdown(ioData->targetSSL);
						SSL_free(ioData->targetSSL);
					}

					ioData->clientCTX = server_SSL_CTX();
					SSL_CTX_set_tlsext_servername_callback(ioData->clientCTX, ServerNameCallback);
					SSL_CTX_set_tlsext_servername_arg(ioData->clientCTX, ioData);
					if (!ioData->clientCTX)
					{
						printf("[-]Failed to create client SSL CTX. ID - %d\n", ioData->key);
					}

					ioData->clientSSL = SSL_new(ioData->clientCTX);
					SSL_set_accept_state(ioData->clientSSL); // to act as SERVER
					SSL_set_bio(ioData->clientSSL, ioData->crBio, ioData->cwBio);

					if (!SSL_is_init_finished(ioData->clientSSL))
					{
						int ret_client = SSL_do_handshake(ioData->clientSSL);

						if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
						{
							DWORD error = WSAGetLastError();
							if (error != WSA_IO_PENDING)
							{
								printf("[-]WSARecv() failed - %d. ID - %d\n", error, ioData->key);
								closesocket(ioData->clientSocket);
								closesocket(ioData->serverSocket);
								delete ioData;
								break;
							}
						}
						else
						{
							printf("[+]WSARecv() client - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
						}
					}

					break;
				}

				status = SSL_get_error(ioData->targetSSL, ret_server);

				printf("[=]SSL_get_error() server - %d. ID - %d\n", status, ioData->key);

				if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
				{
					bio_read = BIO_read(ioData->swBio, Buf, BUFFER_SIZE);

					if (bio_read > 0)
					{
						if (detailLog)
						{
							printf("[+]BIO_read() server - %d bytes. ID - %d\n", bio_read, ioData->key);
						}

						memcpy(ioData->wsaServerSendBuf.buf, Buf, bio_read);
						ioData->wsaServerSendBuf.len = bio_read;

						if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
						{
							int error = WSAGetLastError();
							if (error != WSA_IO_PENDING)
							{
								printf("[-]WSASend() failed - %d. ID - %d\n", error, ioData->key);
								closesocket(ioData->clientSocket);
								closesocket(ioData->serverSocket);
								delete ioData;
								break;
							}
						}
						else
						{
							printf("[+]WSASend() server - %d bytes. ID - %d\n", ioData->bytesSend, ioData->key);
						}
					}
					else
					{
						ioData->bytesRecv = 0;
						ioData->wsaServerRecvBuf.len = BUFFER_SIZE;

						ZeroMemory(ioData->sRecvBuffer, BUFFER_SIZE);

						if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
						{
							int error = WSAGetLastError();
							if (error != WSA_IO_PENDING)
							{
								printf("[-]WSARecv() failed - %d. ID - %d\n", error, ioData->key);
								closesocket(ioData->clientSocket);
								closesocket(ioData->serverSocket);
								delete ioData;
								break;
							}
						}
						else
						{
							printf("[+]WSARecv() server - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
						}
					}
				}
				else if (status == SSL_ERROR_SSL)
				{
					printf("[-]SSL_get_error() server - %s. ID - %d\n", ERR_error_string(ERR_get_error(), NULL), ioData->key);
					break;
				}
				else
				{
					printf("[-]SSL_get_error() server - %d. ID - %d\n", status, ioData->key);
					break;
				}
			}
			else if (detailLog)
			{
				printf("[+]SSL handshake with server done. ID - %d\n", ioData->key);
			}

			break;
		}

		case CLIENT_SSL_HANDSHAKE:
		{
			if (strlen(ioData->cRecvBuffer) > 0)
			{
				ioData->clientRecvFlag = FALSE;
				int bio_write = BIO_write(ioData->crBio, ioData->cRecvBuffer, bytesTransferred);
				if (bio_write > 0)
				{
					printf("[+]BIO_write() client - %d bytes. ID - %d\n", bio_write, ioData->key);
				}
				memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
			}

			if (!SSL_is_init_finished(ioData->clientSSL))
			{
				char buffer[BUFFER_SIZE] = { '\0' };
				int bio_read = 0, ret_client, status;

				ret_client = SSL_do_handshake(ioData->clientSSL);
				if (ret_client == 1)
				{
					printf("[+]SSL handshake done with client. ID - %d\n", ioData->key);

					// check if alpn is negotiated after handshake
					const unsigned char* alpn = NULL;
					unsigned int alpnlen = 0;

					if (alpn == NULL)
					{
						SSL_get0_alpn_selected(ioData->clientSSL, &alpn, &alpnlen);
					}

					if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0)
					{
						printf("[-]h2 is not negotiated. ID - %d\n", ioData->key);
						closesocket(ioData->clientSocket);
						delete ioData;
						break;
					}
					else
					{
						printf("[+]ALPN negotiated with client. ID - %d\n", ioData->key);
					}

					ioData->server_session_data = create_http2_server_session_data(ioData->clientCTX, ioData->clientSocket, g_addr, g_addrlen);

					initialize_server_nghttp2_session(ioData);

					// send connection headers to client
					if (send_server_connection_header(ioData->server_session_data) != 0 ||
						server_session_send(ioData->server_session_data) != 0) {
						delete_http2_server_session_data(ioData->server_session_data, ioData->clientSSL);
						break;
					}

					ioData->ioOperation = IO;
					ioData->clientRecvFlag = TRUE;
					ioData->wsaClientRecvBuf.len = BUFFER_SIZE;

					ZeroMemory(ioData->cRecvBuffer, BUFFER_SIZE);

					if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
					{
						int error = WSAGetLastError();
						if (error != WSA_IO_PENDING)
						{
							printf("[-]WSARecv() failed - %d. ID - %d\n", error, ioData->key);
							closesocket(ioData->clientSocket);
							delete ioData;
							break;
						}
					}
					else
					{
						printf("[+]WSARecv() client - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
					}
				}

				status = SSL_get_error(ioData->clientSSL, ret_client);

				if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
				{
					bio_read = BIO_read(ioData->cwBio, buffer, BUFFER_SIZE);
					if (bio_read > 0)
					{
						printf("[+]BIO_read() client - %d bytes. ID - %d\n", bio_read, ioData->key);

						memcpy(ioData->wsaClientSendBuf.buf, buffer, bio_read);
						ioData->wsaClientSendBuf.len = bio_read;

						ZeroMemory(buffer, BUFFER_SIZE);

						if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
						{
							int error = WSAGetLastError();
							if (error != WSA_IO_PENDING)
							{
								printf("[-]WSASend() failed - %d. ID - %d\n", error, ioData->key);
								closesocket(ioData->clientSocket);
								delete ioData;
								break;
							}
						}
						else
						{
							printf("[+]WSASend() client - %d bytes. ID - %d\n", ioData->bytesSend, ioData->key);
						}
					}
					else if (!ioData->clientRecvFlag)
					{
						ioData->bytesRecv = 0;
						ioData->clientRecvFlag = TRUE;
						ioData->wsaClientRecvBuf.len = BUFFER_SIZE;

						if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
						{
							int error = WSAGetLastError();
							printf("[-]WSARecv() client IO pending. ID - %d\n", ioData->key);
							if (error != WSA_IO_PENDING)
							{
								printf("[-]WSARecv() failed - %d. ID - %d\n", error, ioData->key);
								closesocket(ioData->clientSocket);
								delete ioData;
								break;
							}
						}
						else
						{
							printf("[+]WSARecv() client - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
						}
					}
				}
				else
				{
					if (status == SSL_ERROR_SSL)
					{
						printf("[-]SSL_get_error() client - %s. ID - %d\n", ERR_error_string(ERR_get_error(), NULL), ioData->key);
						break;
					}
					else if (status == SSL_ERROR_SYSCALL)
					{
						printf("[-]SSL_get_error() client - %s. ID - %d\n", ERR_error_string(ERR_get_error(), NULL), ioData->key);
						SSL_shutdown(ioData->clientSSL);
						break;
					}
				}
				break;
			}
			else
			{
				printf("[+]SSL handshake done with client 2. ID - %d\n", ioData->key);
			}
			break;
		}

		case IO:
		{
			printf("[=]IO. bytesTransferred: %d\n", bytesTransferred);

			int ssl_read, bio_write, nghttp2_read, error;

			if (strlen(ioData->cRecvBuffer) > 0)
			{
				bio_write = BIO_write(ioData->crBio, ioData->cRecvBuffer, bytesTransferred);
				if (bio_write > 0)
				{
					//ioData->clientRecvFlag = FALSE;
					printf("[+]BIO_write() client - %d bytes. ID - %d\n", bio_write, ioData->key);
					
					ZeroMemory(ioData->cRecvBuffer, BUFFER_SIZE);
					ssl_read = SSL_read(ioData->clientSSL, ioData->cRecvBuffer, BUFFER_SIZE);

					if (ssl_read <= 0)
					{
						error = SSL_get_error(ioData->clientSSL, ssl_read);
						printf("[-]SSL_read() client - %d. ID - %d\n", error, ioData->key);
						if ((error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) && !ioData->clientRecvFlag)
						{
							ioData->bytesRecv = 0;
							ioData->clientRecvFlag = TRUE;
							ZeroMemory(ioData->cRecvBuffer, BUFFER_SIZE);

							if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
							{
								int error = WSAGetLastError();
								if (error != WSA_IO_PENDING)
								{
									printf("[-]WSARecv() failed - %d. ID - %d\n", error, ioData->key);
									closesocket(ioData->clientSocket);
									delete ioData;
									break;
								}
							}
							else
							{
								printf("[+]WSARecv() client - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
							}
							break;
						}
						else if (error == SSL_ERROR_SSL)
						{
							printf("[!]SSL_get_error() client - %s. ID - %d\n", ERR_error_string(ERR_get_error(), NULL), ioData->key);
							break;
						}
						else if (error == SSL_ERROR_SYSCALL)
						{
							printf("[!]SSL_get_error() client - %s. ID - %d\n", ERR_error_string(ERR_get_error(), NULL), ioData->key);
							SSL_shutdown(ioData->clientSSL);
							break;
						}
						else
						{
							printf("[!]SSL_get_error() client - %d. ID - %d\n", error, ioData->key);
							break;
						}
					}
					else
					{
						printf("[+]SSL_read client - %d bytes. ID - %d\n", ssl_read, ioData->key);
						nghttp2_read = nghttp2_session_mem_recv2(ioData->server_session_data->session, (uint8_t*)ioData->cRecvBuffer, ssl_read);
						if (nghttp2_read < 0) {
							printf("[-]Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
							delete_http2_server_session_data(ioData->server_session_data, ioData->clientSSL);
							break;
						}
						memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
						if (server_session_send(ioData->server_session_data) != 0) {
							printf("session_send 2\n");
							delete_http2_server_session_data(ioData->server_session_data, ioData->clientSSL);
							break;
						}
						while ((ssl_read = SSL_read(ioData->clientSSL, ioData->cRecvBuffer, BUFFER_SIZE)) > 0)
						{
							printf("[+]ssl_read client - %d bytes. ID - %d\n", ssl_read, ioData->key);
							nghttp2_read = nghttp2_session_mem_recv2(ioData->server_session_data->session, (uint8_t*)ioData->cRecvBuffer, ssl_read);
							if (nghttp2_read < 0) {
								printf("[-]Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
								delete_http2_server_session_data(ioData->server_session_data, ioData->clientSSL);
								break;
							}
							memset(ioData->cRecvBuffer, '\0', BUFFER_SIZE);
							if (server_session_send(ioData->server_session_data) != 0) {
								printf("session_send 2\n");
								delete_http2_server_session_data(ioData->server_session_data, ioData->clientSSL);
								break;
							}
						}
					}
				}
				else
				{
					printf("[-]BIO_write() client. ID - %d\n", ioData->key);
					break;
				}

				ioData->clientRecvFlag = FALSE;
			}

			if (ioData->ioFlag == STREAM_CLOSE && !ioData->clientRecvFlag)
			{
				ioData->clientRecvFlag = TRUE;
				ioData->wsaClientRecvBuf.len = BUFFER_SIZE;
				ZeroMemory(ioData->cRecvBuffer, BUFFER_SIZE);
				if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
				{
					int error = WSAGetLastError();
					if (error != WSA_IO_PENDING)
					{
						printf("[-]WSARecv() failed - %d. ID - %d\n", error, ioData->key);
						closesocket(ioData->clientSocket);
						delete ioData;
						break;
					}
				}
				else
				{
					printf("[+]WSARecv() client (IO) - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
				}
			}

			break;
		}

		case SERVER_IO:
		{
			printf("[=]SERVER_IO. bytesTransferred: %d\n", bytesTransferred);
			
			int nghttp2_read, bio_write, ssl_read, error;

			if (strlen(ioData->sRecvBuffer) > 0)
			{
				//ioData->ioFlag = SERVER;
				
				bio_write = BIO_write(ioData->srBio, ioData->sRecvBuffer, bytesTransferred);

				if (bio_write > 0)
				{
					ioData->serverRecvFlag = FALSE;
					printf("[+]bio_write SERVER_IO - %d bytes. ID - %d\n", bio_write, ioData->key);
					
					ZeroMemory(ioData->sRecvBuffer, BUFFER_SIZE);

					ssl_read = SSL_read(ioData->targetSSL, ioData->sRecvBuffer, BUFFER_SIZE);

					if (ssl_read <= 0)
					{
						error = SSL_get_error(ioData->targetSSL, ssl_read);
						printf("[=]SSL_read server error - %d\n", error);

						if ((error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) && !ioData->serverRecvFlag)
						{
							ioData->serverRecvFlag = TRUE;
							ioData->wsaServerRecvBuf.len = BUFFER_SIZE;
							ZeroMemory(ioData->sRecvBuffer, BUFFER_SIZE);

							if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
							{
								int error = WSAGetLastError();
								printf("[-]WSARecv() server IO pending 2\n");
								if (error != WSA_IO_PENDING)
								{
									printf("[-]WSARecv() server IO - %d\n", error);
									closesocket(ioData->serverSocket);
									SSL_free(ioData->targetSSL);
									delete ioData;
									break;
								}
							}
							else
							{
								printf("[+]WSARecv() server 2 (SERVER_IO) - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
							}
							break;
						}
						else if (error == SSL_ERROR_SSL)
						{
							printf("[!]SSL_get_error() server - %s\n", ERR_error_string(ERR_get_error(), NULL));
							return -1;
						}
						else if (error == SSL_ERROR_SYSCALL)
						{
							printf("[!]SSL_get_error() server - %s\n", ERR_error_string(ERR_get_error(), NULL));
							return -1;
						}
						else
						{
							break;
						}
					}
					else
					{
						ioData->serverRecvFlag = TRUE;

						printf("[+]ssl_read SERVER_IO - %d bytes. ID - %d\n", ssl_read, ioData->key);
						nghttp2_read = nghttp2_session_mem_recv2(ioData->client_session_data->session, (uint8_t*)ioData->sRecvBuffer, ssl_read);
						if (nghttp2_read < 0) {
							printf("[-]Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
							delete_http2_client_session_data(ioData->client_session_data);
							break;
						}
						memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
						if (client_session_send(ioData->client_session_data) != 0) {
							printf("[-]session_send 2\n");
							delete_http2_client_session_data(ioData->client_session_data);
							break;
						}
						while ((ssl_read = SSL_read(ioData->targetSSL, ioData->sRecvBuffer, BUFFER_SIZE)) > 0)
						{
							printf("[+]ssl_read SERVER_IO - %d bytes. ID - %d\n", ssl_read, ioData->key);
							nghttp2_read = nghttp2_session_mem_recv2(ioData->client_session_data->session, (uint8_t*)ioData->sRecvBuffer, ssl_read);
							if (nghttp2_read < 0) {
								printf("[-]Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
								delete_http2_client_session_data(ioData->client_session_data);
								break;
							}
							memset(ioData->sRecvBuffer, '\0', BUFFER_SIZE);
							if (client_session_send(ioData->client_session_data) != 0) {
								printf("[-]session_send 2\n");
								delete_http2_client_session_data(ioData->client_session_data);
								break;
							}
						}

						ioData->serverRecvFlag = FALSE;
					}
					
				}
				else
				{
					printf("[-]BIO_write() server failed. ID - %d\n", ioData->key);
					break;
				}
			}
			/*else
			{
				printf("[-]server recv buffer empty. ID - %d\n", ioData->key);
			}*/

			if (!ioData->serverRecvFlag)
			{
				ioData->serverRecvFlag = TRUE;
				ZeroMemory(ioData->sRecvBuffer, BUFFER_SIZE);

				if (WSARecv(ioData->serverSocket, &ioData->wsaServerRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
				{
					int error = WSAGetLastError();
					printf("[-]WSARecv() server IO pending 3\n");
					if (error != WSA_IO_PENDING)
					{
						printf("[-]WSARecv() server - %d\n", error);
						closesocket(ioData->serverSocket);
						SSL_free(ioData->targetSSL);
						delete ioData;
						break;
					}
				}
				else
				{
					printf("[+]WSARecv() server 3 (SERVER_IO) - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
				}
				break;
			}

			break;
		}

		case CLIENT_IO:
		{
			printf("[=]CLIENT_IO. bytesTransferred: %d\n", bytesTransferred);

			int nghttp2_read, bio_write, ssl_read, error;

			if (strlen(ioData->cRecvBuffer) > 0)
			{
				ioData->ioFlag = CLIENT;
				bio_write = BIO_write(ioData->crBio, ioData->cRecvBuffer, bytesTransferred);

				if (bio_write > 0)
				{
					ioData->clientRecvFlag = FALSE;
					printf("[+]bio_write client - %d bytes. ID - %d\n", bio_write, ioData->key);
					ZeroMemory(ioData->cRecvBuffer, BUFFER_SIZE);

					ssl_read = SSL_read(ioData->clientSSL, ioData->cRecvBuffer, BUFFER_SIZE);

					if (ssl_read <= 0)
					{
						error = SSL_get_error(ioData->clientSSL, ssl_read);
						printf("[=]SSL_read client error - %d\n", error);

						if ((error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) && !ioData->clientRecvFlag)
						{
							ioData->bytesRecv = 0;
							ioData->clientRecvFlag = TRUE;
							ZeroMemory(ioData->cRecvBuffer, BUFFER_SIZE);

							if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
							{
								int error = WSAGetLastError();
								printf("[-]WSARecv() client IO pending 2\n");
								if (error != WSA_IO_PENDING)
								{
									printf("[-]WSARecv() client IO - %d\n", error);
									closesocket(ioData->clientSocket);
									SSL_free(ioData->clientSSL);
									delete ioData;
									break;
								}
							}
							else
							{
								printf("[+]WSARecv() client 2 - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
							}
							break;
						}
						else if (error == SSL_ERROR_SSL)
						{
							printf("[!]SSL_get_error() client - %s\n", ERR_error_string(ERR_get_error(), NULL));
							return -1;
						}
						else if (error == SSL_ERROR_SYSCALL)
						{
							printf("[!]SSL_get_error() client - %s\n", ERR_error_string(ERR_get_error(), NULL));
							SSL_shutdown(ioData->clientSSL);
							return -1;
						}
						else
						{
							printf("[!]SSL_get_error() client - %d\n", error);
							break;
						}
					}
					else
					{
						ioData->clientRecvFlag = TRUE;

						printf("[+]ssl_read client - %d bytes. ID - %d\n", ssl_read, ioData->key);
						nghttp2_read = nghttp2_session_mem_recv2(ioData->server_session_data->session, (uint8_t*)ioData->cRecvBuffer, ssl_read);
						if (nghttp2_read < 0) {
							printf("[-]Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
							delete_http2_server_session_data(ioData->server_session_data, ioData->clientSSL);
							break;
						}
						ZeroMemory(ioData->cRecvBuffer, BUFFER_SIZE);
						if (server_session_send(ioData->server_session_data) != 0) {
							printf("[-]session_send 2\n");
							delete_http2_server_session_data(ioData->server_session_data, ioData->clientSSL);
							break;
						}
						while ((ssl_read = SSL_read(ioData->clientSSL, ioData->cRecvBuffer, BUFFER_SIZE)) > 0)
						{
							printf("[+]ssl_read client - %d bytes. ID - %d\n", ssl_read, ioData->key);
							nghttp2_read = nghttp2_session_mem_recv2(ioData->server_session_data->session, (uint8_t*)ioData->cRecvBuffer, ssl_read);
							if (nghttp2_read < 0) {
								printf("[-]Fatal error: %s\n", nghttp2_strerror((int)nghttp2_read));
								delete_http2_server_session_data(ioData->server_session_data, ioData->clientSSL);
								break;
							}
							ZeroMemory(ioData->cRecvBuffer, BUFFER_SIZE);
							if (server_session_send(ioData->server_session_data) != 0) {
								printf("[-]session_send 2\n");
								delete_http2_server_session_data(ioData->server_session_data, ioData->clientSSL);
								break;
							}
						}
					}
					ioData->clientRecvFlag = FALSE;
				}
				else
				{
					printf("[-]BIO_write() client failed. ID - %d\n", ioData->key);
					break;
				}
			}
			else
			{
				printf("[-]client recv buffer empty. ID - %d\n", ioData->key);
			}

			if (!ioData->clientRecvFlag)
			{
				ioData->clientRecvFlag = TRUE;
				ZeroMemory(ioData->cRecvBuffer, BUFFER_SIZE);

				if (WSARecv(ioData->clientSocket, &ioData->wsaClientRecvBuf, 1, &ioData->bytesRecv, &flags, &ioData->overlapped, NULL) == SOCKET_ERROR)
				{
					int error = WSAGetLastError();
					printf("[-]WSARecv() client IO pending 3\n");
					if (error != WSA_IO_PENDING)
					{
						printf("[-]WSARecv() client - %d\n", error);
						closesocket(ioData->clientSocket);
						delete ioData;
						break;
					}
				}
				else
				{
					printf("[+]WSARecv() client 3 (CLIENT_IO) - %d bytes. ID - %d\n", ioData->bytesRecv, ioData->key);
				}
				break;
			}

			break;
		}

		case CLIENT_SEND:
		{
			printf("[=]CLIENT_SEND. bytesTransferred: %d\n", bytesTransferred);

			if (!ioData->clientSendFlag)
			{
				int bio_read;
				ZeroMemory(ioData->cTempBuffer, BUFFER_SIZE);
				bio_read = BIO_read(ioData->crBio, ioData->cTempBuffer, BUFFER_SIZE);

				if (bio_read > 0)
				{
					printf("[+]BIO_read() CLIENT_SEND - %d bytes. ID - %d\n", bio_read, ioData->key);
					memcpy(ioData->cSendBuffer, ioData->cTempBuffer, bio_read);
					ioData->wsaClientSendBuf.len = bio_read;
					if (WSASend(ioData->clientSocket, &ioData->wsaClientSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
					{
						int error = WSAGetLastError();
						if (error != WSA_IO_PENDING)
						{
							printf("[-]WSASend() failed - %d. ID - %d\n", error, ioData->key);
							closesocket(ioData->clientSocket);
							delete ioData;
							break;
						}
					}
					else
					{
						printf("[+]WSASend() CLIENT_SEND - %d bytes. ID - %d\n", ioData->bytesSend, ioData->key);
					}
				}
				else
				{
					printf("[-]BIO_read() CLIENT_SEND - %d. ID - %d\n", ERR_get_error(), ioData->key);
				}
			}

			break; 
		}

		case SERVER_SEND:
		{
			printf("[=]CLIENT_SEND. bytesTransferred: %d\n", bytesTransferred);

			int bio_read = BIO_read(ioData->swBio, ioData->sTempBuffer, BUFFER_SIZE);

			if (bio_read > 0)
			{

				printf("[+]bio_read SERVER_SEND: %d\n", bio_read);
				memcpy(ioData->sSendBuffer, ioData->sTempBuffer, bio_read);

				if (ioData->ioFlag == SERVER)
				{
					ioData->ioOperation = SERVER_IO;
				}
				else if (ioData->ioFlag == CLIENT)
				{
					ioData->ioOperation = CLIENT_IO;
				}

				ioData->wsaClientSendBuf.len = bio_read;

				if (bio_read == BUFFER_SIZE)
				{
					ioData->ioOperation = SERVER_SEND;
				}

				if (WSASend(ioData->serverSocket, &ioData->wsaServerSendBuf, 1, &ioData->bytesSend, 0, &ioData->overlapped, NULL) == SOCKET_ERROR)
				{
					int error = WSAGetLastError();
					if (error != WSA_IO_PENDING)
					{
						printf("Failed to send response: %d\n", error);
						closesocket(ioData->serverSocket);
						break;
					}
				}
				else
				{
					printf("[+]WSASend SERVER_SEND: %d bytes\n", ioData->bytesSend);
				}
			}

			break;
		}

		default:
			break;
		}
	}
}