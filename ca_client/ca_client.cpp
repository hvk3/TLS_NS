#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <set>
#include <map>
#include <fstream>
#include <sstream>
#include <assert.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

using namespace std;

#define REGISTRATION_PORT 5555
#define IRC_PORT 5556
#define MAX 1024 * 16
#define FILE_SIZE 5000000
#define FAIL -1

bool isLoggedIn = false;
char server_host[MAX];
int r;
string signed_cert_fname = "";

map <string, int> user_sock;
map <int, string> sock_user;
map <int, SSL*> sock_SSL;


const SSL_CTX* InitCTX()
{
	const SSL_METHOD *method;
	const SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
	SSL_load_error_strings();			/* Bring in and register error messages */
	method = SSLv23_client_method();		/* Create new client-method instance */
	ctx = SSL_CTX_new(method);			/* Create new context */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

const SSL_CTX* InitServerCTX()
{
	const SSL_METHOD *method;
	const SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */
	SSL_load_error_strings();			/* load all error messages */
	method = SSLv23_server_method();		/* create new server-method instance */
	ctx = SSL_CTX_new(method);			/* create new context from method */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate.\n");
		abort();
	}
}

int sendData(string message, int sock)
{
	const char* info = message.c_str();
	if (write(sock, info, strlen(info) + 1) == -1)
		return -1;
	return 0;
}

int senderSocket(int port_number)
{
	int socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);
	int enable = 1;
	if (setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
		return -1;
	struct sockaddr_in server_address;
	memset(&server_address, '0', sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(port_number);
	if (socket_descriptor < 0)
	{
		printf("Socket creation failed.\n");
		return -1;
	}
	if (inet_pton(AF_INET, server_host, &server_address.sin_addr) <= 0)
	{
		printf("Invalid or unsupported address.\n");
		return -1;
	}
	if (connect(socket_descriptor, (sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		printf("Connection failed. Please try again later.\n");
		return -1;
	}
	return socket_descriptor;
}

int listenerSocket(int port_number)
{
	struct sockaddr_in addr;
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port_number);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sd, (sockaddr*)&addr, sizeof(addr)))
	{
		cout << "Port binding failed." << endl;
		return -1;
	}
	if (listen(sd, 100))
	{
		cout << "Port listening failed." << endl;
		return -1;
	}
	cout << "Listening on port " << port_number << endl;
	return sd;
}

void* recv_m(void* socket_descriptor)
{
	int sock = *(int*)socket_descriptor, bytes;
	char buffer[MAX];
	SSL *ssl = sock_SSL[sock];

	while (1)
	{
		bytes = SSL_read(ssl, buffer, sizeof(buffer));
		if (bytes <= 0 || strlen(buffer) == 0)
			continue;
		cout << sock_user[SSL_get_fd(ssl)] << ": " << buffer << endl;
		buffer[0] = '\0';
	}
	return 0;
}

void* setupTLS(void* socket_descriptor)
{
	int sock = *(int*)socket_descriptor;
	char buffer[MAX];

	const SSL_CTX *ctx = InitCTX();
	SSL *ssl = SSL_new((SSL_CTX*)ctx);
	SSL_set_fd(ssl, sock);

	if (SSL_connect(ssl) <= 0)
		abort();
	sock_SSL[sock] = ssl;
	// Request secure communication line.
	string check = "Request for certificate.";
	const char* x = check.c_str();
	SSL_write(ssl, (char*)x, strlen((char*)x));

	// Receive certificate from server
	SSL_read(ssl, buffer, sizeof(buffer));

	string check_cert(buffer), fname = "check_cert_" + to_string(sock) + ".pem";
	ofstream file(fname);
	file << check_cert;
	file.flush();
	
	string exec = "openssl verify -CAfile ../ca_server/cacert.pem " + fname + " > out";
	system(exec.c_str());

	ifstream cfile("out");
	string content((istreambuf_iterator<char>(cfile)), (std::istreambuf_iterator<char>())), verified = "";
	if (content.find("OK") != string::npos)
		verified = "VERIFIED";
	else
		verified = "ERROR";

	x = verified.c_str();
	SSL_write(ssl, (char*)x, strlen((char*)x));

	if (verified == "VERIFIED")
	{
		cout << "Secure channel established.\nUse /secret_msg for sending messages on this channel." << endl;
		pthread_t p;
		pthread_create(&p, NULL, recv_m, (void*)&sock);
	}
	else
		cout << "Invalid certificate." << endl;
}

void* listenforTLS(void* socket_descriptor)
{
	int sock = *(int*)socket_descriptor, flag = 0;
	char buffer[MAX];

	string cert = signed_cert_fname, key = "server_" + to_string(r) + "_key.pem";
	const SSL_CTX* ctx = InitServerCTX();
	LoadCertificates((SSL_CTX*)ctx, (char*)cert.c_str(), (char*)key.c_str());
	SSL* ssl = SSL_new((SSL_CTX*)ctx);
	SSL_set_fd(ssl, sock);

	while (SSL_accept(ssl) <= 0);
	sock_SSL[sock] = ssl;

	SSL_read(ssl, buffer, sizeof(buffer));
	string req(buffer);
	if (req == "Request for certificate.")
	{
		buffer[0] = '\0';
		ifstream ifs(signed_cert_fname);
		string content((istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

		const char* x = content.c_str();
		SSL_write(ssl, (char*)x, strlen((char*)x));
		
		SSL_read(ssl, buffer, sizeof(buffer));
		string verification(buffer);
		if (verification.find("VERIFIED") != string::npos)
		{
			cout << "Secure channel established.\nUse /secret_msg for sending messages on this channel." << endl;
			pthread_t p;
			pthread_create(&p, NULL, recv_m, (void*)&sock);
		}
	}
}

void* receive(void* socket_descriptor)
{
	int sock = *(int*)socket_descriptor;
	char buffer[MAX], *lock;
	while (1)
	{
		if (!read(sock, buffer, sizeof(buffer)))
			break;
		bool to_print = true;
		string message(buffer);
		if (message.substr(0, 6) == "Listen" || message.substr(0, 4) == "Send")
		{
			to_print = false;
			string m = message;
			string delimiter = " ";
			for (int i = 0; i < 2; i++)
				message.erase(0, message.find(delimiter) + delimiter.length());
			string other_user = message.substr(0, message.find(delimiter));
			for (int i = 0; i < 3; i++)
				message.erase(0, message.find(delimiter) + delimiter.length());
			int port_number = stoi(message.substr(0, message.find(delimiter)));

			if (m.substr(0, 4) == "Send")
			{
				int sock = senderSocket(port_number);
				user_sock[other_user] = sock;
				sock_user[sock] = other_user;
				if (sock != -1)
				{
					pthread_t send;
					pthread_create(&send, NULL, setupTLS, (void*)&sock);
				}
			}
			else if (m.substr(0, 6) == "Listen")
			{
				int sock = listenerSocket(port_number), sock_d = -1;
				if (sock != -1)
				{
					while (sock_d == -1)
						sock_d = accept(sock, (sockaddr*)NULL, NULL);
					user_sock[other_user] = sock_d;
					sock_user[sock_d] = other_user;
					close(sock);
					pthread_t receive;
					pthread_create(&receive, NULL, listenforTLS, (void*)&sock_d);
				}
			}
		}

		if (message == "")
			message = "You have no unread messages.";
		if (to_print)
		{
			if (message.substr(0, 37) == "You have been successfully logged in.")
				cout << message.substr(0, 37) << endl;
			else
				cout << message << endl;
		}

		if (message == "You have been successfully logged out.")
			isLoggedIn = false;

		else if (message.substr(0, 37) == "You have been successfully logged in.")
		{
			isLoggedIn = true;
			message.erase(0, 38);
			string signed_cert = message;
			string fname = "signed_server_" + to_string(r) + ".pem";
			ofstream file(fname);
			file << signed_cert;
			file.flush();
			cout << "Your signed certificate is stored in " + fname << endl;
			signed_cert_fname = fname;
		}
		else
			continue;
	}
}

int main(int argc, char *argv[])
{
	ios::sync_with_stdio(0);
	srand(time(NULL));

	if (argc != 2)
	{
		cout << "Usage: " << argv[0] << " <Server IP address>\n";
		return -1;
	}
	strcpy(server_host, argv[1]);

	SSL_library_init();

	int IRC_socket = senderSocket(IRC_PORT);
	if (IRC_socket == -1)
		exit(0);
	int registration_socket = senderSocket(REGISTRATION_PORT);
	if (registration_socket == -1)
		exit(0);

	cout << "Enter certificate details:" << endl;
	r = rand() % 10000;
	string query = "openssl req -config openssl-client.cnf -newkey rsa:2048 -sha256 -nodes -out server_" + to_string(r) + ".csr -outform PEM -keyout server_" + to_string(r)\
	+ "_key.pem";
	system(query.c_str());

	string in;

	cout << "\nHey there! Welcome to sampleIRC with CA!\n";
	cout << "Here\'s a list of commands to get you started:\n";
	cout << "/login <username> <password>: Log in to IRC.\n";
	cout << "/logout: Log out from IRC.\n";
	cout << "/who: List all users online.\n";
	cout << "/msg <username> <message>: Send <message> to <username>.\n";
	cout << "/recv_msg: Receive all messages that were sent while you were logged out.\n";
	cout << "/register <username> <password>: Create a new account.\n";
	cout << "/rqst_p2pchannel <username>: Request for secure channel with <username>.\n";
	cout << "/exit: Exit portal.\nYou can start now.\n";

	pthread_t IRC_receive, reg_receive;
	pthread_create(&reg_receive, NULL, receive, (void*)&registration_socket);
	pthread_create(&IRC_receive, NULL, receive, (void*)&IRC_socket);

	while (1)
	{
		getline(cin, in);

		if (in.substr(0, 9) == "/register")
		{
			if (sendData(in, registration_socket) == -1)
			{
				cout << "Connection with server is down. Exiting.\n";
				close(registration_socket);
				close(IRC_socket);
				exit(0);
			}
		}
		else if (in == "/exit")
		{
			if (isLoggedIn)
				cout << "Log out before exiting." << endl;
			else
			{
				cout << "Goodbye!" << endl;
				exit(0);
			}
		}
		else if (in == "/logout" || in.substr(0, 4) == "/msg" || in == "/recv_msg" || in == "/who" || in.substr(0, 16) == "/rqst_p2pchannel")
		{
			if (isLoggedIn)
			{
				if (sendData(in, IRC_socket) == -1)
				{
					cout << "Connection with server is down. Exiting.\n";
					close(registration_socket);
					close(IRC_socket);
					exit(0);
				}
				if (in == "/who")
					cout << "List of online users:" << endl;
				if (in == "/all_users")
					cout << "All users:" << endl;
			}
			else
				cout << "Please log in first.\n";
		}
		else if (in.substr(0, 6) == "/login")
		{
			if (!isLoggedIn)
			{
				cout << "Getting certificates signed by CA. Please wait." << endl;
				string fname = "server_"  + to_string(r) + ".csr";
				ifstream ifs(fname);
				string content((istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
				in += " " + content;
				if (sendData(in, IRC_socket) == -1)
				{
					cout << "Connection with server is down. Exiting.\n";
					close(registration_socket);
					close(IRC_socket);
					exit(0);
				}
			}
			else
				cout << "Please log out first.\n";
		}
		else if (in.substr(0, 11) == "/secret_msg")
		{
			if (isLoggedIn)
			{
				string command(in), delimiter = " ";
				command.erase(0, command.find(delimiter) + delimiter.length());
				string receiver = command.substr(0, command.find(delimiter));
				if (receiver.length() == 0)
				{
					cout << "No receiver specified." << endl;
					continue;
				}
				command.erase(0, command.find(delimiter) + delimiter.length());
				string m = command;
				if (m.length() == 0)
				{
					cout << "No message to send." << endl;
					continue;
				}
				if (user_sock.count(receiver) == 0)
				{
					cout << "No such user." << endl;
					continue;
				}
				int sock_r = user_sock[receiver];
				SSL *ssl = sock_SSL[sock_r];

				const char *m_s = m.c_str();				
				if (SSL_write(ssl, (char*)m_s, strlen((char*)m_s)) > 0)
					cout << "Your message was successfully delivered." << endl;
			}
			else
				cout << "Please log in first.\n";
		}
		else if (in.length() == 0)
			continue;
		else
			cout << "This command is not a part of the commands supported. Try again." << endl;
	}
	close(registration_socket);
	close(IRC_socket);
	return 0;
}