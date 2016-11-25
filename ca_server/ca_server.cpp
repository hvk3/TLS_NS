#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <sstream>
#include <stdio.h>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#define FAIL -1
#define IRC_PORT 5556
#define MAX_SIZE 1024 * 16
#define REGISTRATION_PORT 5555

using namespace std;

map <string, pair <string, bool> > users;
map <string, pair <string, bool> >::iterator users_iter;

map <string, int> user_to_conn;
map <int, string> conn_to_user;

map <string, queue <string> > personal_chat;

int counter = 0;
int P2P_PORT = 12000;

pthread_mutex_t setup_channel, save_users, logout_user, login_user, personal_message, clear_queue, logged_in_users;

int loadUsers()
{
	string str;
	vector <string> records;
	ifstream file("records.txt");
	if (!file.good())
		return -1;
	while (file >> str)
		records.push_back(str);
	for (int i = 0; i < records.size(); i += 2)
		users[records[i]] = make_pair(records[i + 1], false);
	return 0;
}

void saveUsers()
{
	fstream file;
	file.open("records.txt", fstream::out);
	for (users_iter = users.begin(); users_iter != users.end(); users_iter++)
	{
		string temp = users_iter -> first + ' ' + users_iter -> second.first;
		file << temp << endl;
	}
	file.close();
}

void* registerUser(void* socket_descriptor)
{
	int sock = *(int*)socket_descriptor;
	char buffer[MAX_SIZE], *lock;
	
	while (1)
	{
		if (read(sock, buffer, sizeof(buffer)) <= 0)
			return 0;
		pthread_mutex_lock(&save_users);
		char *temp = strtok_r(buffer, " ", &lock);
		cout << "Command received: " << temp << endl;

		temp = strtok_r(NULL, " ", &lock);
		if (!temp)
		{
			char message[] = "No username provided for registration.";
			write(sock, message, strlen(message) + 1);
			pthread_mutex_unlock(&save_users);
			return 0;
		}
		string username(temp);
	
		temp = strtok_r(NULL, " ", &lock);
		if (!temp)
		{
			char message[] = "No password provided for registration.";
			write(sock, message, strlen(message) + 1);
			pthread_mutex_unlock(&save_users);
			return 0;
		}
		string password(temp), res;
		if (users.count(username) > 0)
			res = "This username is already in use. Try a different one.";
		else
		{
			users[username] = make_pair(password, false);
			saveUsers();
			res = "You have been successfully registered. Login to continue.";
		}
		const char* info = res.c_str();
		write(sock, info, strlen(info) + 1);
		pthread_mutex_unlock(&save_users);
	}
}

int loginUser(char *buffer, int sock)
{
	char *lock;
	pthread_mutex_lock(&login_user);
	string command(buffer), delimiter = " ";
	command.erase(0, command.find(delimiter) + delimiter.length());
	string temp = command.substr(0, command.find(delimiter));

	if (temp.length() == 0)
	{
		char message[] = "No username provided for logging in.";
		write(sock, message, strlen(message) + 1);
		pthread_mutex_unlock(&login_user);
		return -1;
	}
	command.erase(0, command.find(delimiter) + delimiter.length());
	string username(temp);
	
	temp = command.substr(0, command.find(delimiter));
	if (temp.length() == 0)
	{
		char message[] = "No password provided for logging in.";
		write(sock, message, strlen(message) + 1);
		pthread_mutex_unlock(&login_user);
		return -1;
	}
	string password(temp), res;
	command.erase(0, command.find(delimiter) + delimiter.length());

	int flag = 0;
	if (!users.count(username) || users[username].first != password)
	{
		res = "These credentials are invalid. Try again.";
		flag = -1;
	}
	else
	{
		if (users[username].second == false)
		{
			users[username].second = true;
			conn_to_user[sock] = username;
			user_to_conn[username] = sock;
			res = "You have been successfully logged in.";
		}
		else
			res = "This user is already logged in.";
	}
	string cert = command;
	string fname = "server_" + to_string(sock) + ".csr";
	ofstream file(fname);
	file << cert;
	file.flush();

	string sys_query = "openssl ca -batch -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out signed_" + fname + ".pem -infiles " + fname;
	system(sys_query.c_str());

	ifstream ifs("signed_" + fname + ".pem");
	string content((istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

	if (res == "You have been successfully logged in.")
		res += " " + content;

	const char* info = res.c_str();
	write(sock, info, strlen(info) + 1);
	pthread_mutex_unlock(&login_user);
	return flag;
}

void logoutUser(int sock)
{
	pthread_mutex_lock(&logout_user);
	string username = conn_to_user[sock];
	users[username].second = false;
	user_to_conn.erase(username);
	conn_to_user.erase(sock);
	string success = "You have been successfully logged out.";
	const char* info = success.c_str();
	write(sock, info, strlen(info) + 1);
	pthread_mutex_unlock(&logout_user);
}

void loggedInUsers(int sock)
{
	pthread_mutex_lock(&logged_in_users);
	vector <string> loggedIn;
	for (users_iter = users.begin(); users_iter != users.end(); users_iter++)
		if (users_iter -> second.second)
			loggedIn.push_back(users_iter -> first);
	string users = "";
	for (int i = 0; i < loggedIn.size(); i++)
	{
		users += loggedIn[i];
		if (i != loggedIn.size() - 1)
			users += "\n";
	}
	const char* info = users.c_str();
	write(sock, info, strlen(info) + 1);
	pthread_mutex_unlock(&logged_in_users);
}

void messageUser(char *buffer, int sock)
{
	pthread_mutex_lock(&personal_message);
	char *lock;
	char *temp = strtok_r(buffer, " ", &lock);

	temp = strtok_r(NULL, " ", &lock);
	if (!temp)
	{
		char message[] = "No receiver provided.";
		write(sock, message, strlen(message) + 1);
		pthread_mutex_unlock(&personal_message);
		return;
	}
	string receiver(temp);
	temp = strtok_r(NULL, " ", &lock);
	if (!temp)
	{
		char message[] = "No message to send.";
		write(sock, message, strlen(message) + 1);
		pthread_mutex_unlock(&personal_message);
		return;
	}
	string message(temp);
	while (temp = strtok_r(NULL, " ", &lock))
	{
		string x(temp);
		message += " " + x;
	}
	message = conn_to_user[sock] + ": " + message;

	if (!users.count(receiver))
	{
		message = "This user doesn\'t exist. Select a different user to message.";
		const char* info = message.c_str();
		write(sock, info, strlen(info) + 1);
		pthread_mutex_unlock(&personal_message);
		return;
	}

	if (users[receiver].second)
	{
		while (users[receiver].second && !personal_chat[receiver].empty())
		{
			string temp = personal_chat[receiver].front();
			personal_chat[receiver].pop();
			const char* info = temp.c_str();
			write(user_to_conn[receiver], info, strlen(info) + 1);
			pthread_mutex_unlock(&personal_message);
			return;
		}
		const char* info = message.c_str();
		write(user_to_conn[receiver], info, strlen(info) + 1);
		pthread_mutex_unlock(&personal_message);
		char temp[] = "Your message has been successfully delivered.";
		write(sock, temp, strlen(temp) + 1);
		return;
	}
	else
	{
		personal_chat[receiver].push(message);
		char message[] = "The user you messaged is currently offline. He can view your message after logging in.";
		write(sock, message, strlen(message) + 1);
	}
	pthread_mutex_unlock(&personal_message);
}

void clearPersonalMessageQueue(int sock)
{
	pthread_mutex_lock(&clear_queue);
	string username = conn_to_user[sock], temp = "";
	queue <string> messages = personal_chat[username];
	while (!messages.empty())
	{
		temp += messages.front();
		messages.pop();
		if (messages.size())
			temp += '\n';
	}
	const char* info = temp.c_str();
	write(sock, info, strlen(info) + 1);
	pthread_mutex_unlock(&clear_queue);
	return;
}

void setupP2P(char* buffer, int sock)
{
	pthread_mutex_lock(&setup_channel);
	char *lock;
	char *temp = strtok_r(buffer, " ", &lock);

	temp = strtok_r(NULL, " ", &lock);
	string receiver(temp);
	if (user_to_conn.count(receiver) == 0)
	{
		const char* msg = "This user isn't logged in/registered.";
		write(sock, msg, strlen(msg) + 1);
		pthread_mutex_unlock(&setup_channel);
		return;
	}
	if (receiver == conn_to_user[sock])
	{
		const char* msg = "The sender and the receiver are the same.";
		write(sock, msg, strlen(msg) + 1);
		pthread_mutex_unlock(&setup_channel);
		return;
	}
	int receiver_sock = user_to_conn[receiver];
	string x1 = "Listen for " + conn_to_user[sock] + " on port " + to_string(P2P_PORT), x2 = "Send to " + receiver + " on port " + to_string(P2P_PORT);
	const char* info = x1.c_str();
	int w1 = write(receiver_sock, info, strlen(info) + 1);
	info = x2.c_str();
	int w2 = write(sock, info, strlen(info) + 1);
	if (w1 <= 0 || w2 <= 0)
	{
		cout << "Channel setup failed." << endl;
		pthread_mutex_unlock(&setup_channel);
		return;
	}
	P2P_PORT++;
	pthread_mutex_unlock(&setup_channel);
}

void *functionHandler(void* socket_descriptor)
{
	int sock = *(int*)socket_descriptor;
	char buffer[MAX_SIZE], input[MAX_SIZE], temp_buffer[MAX_SIZE];
	
	while (1)
	{
		if (!read(sock, buffer, sizeof(buffer)))
			return 0;
	
		strcpy(temp_buffer, buffer);
		char *lock;
		char *temp = strtok_r(temp_buffer, " ", &lock);

		string command(temp);
		cout << "Command received: " << command << endl;
		if (command == "/login")
			loginUser(buffer, sock);
		else if (command == "/logout")
			logoutUser(sock);
		else if (command == "/who")
			loggedInUsers(sock);
		else if (command == "/msg")
			messageUser(buffer, sock);
		else if (command == "/recv_msg")
			clearPersonalMessageQueue(sock);
		else if (command == "/rqst_p2pchannel")
			setupP2P(buffer, sock);
	}
	cout << "Closing connection." << endl;
	close(sock);
}

int OpenListener(int port_number)
{
	struct sockaddr_in addr;
	int sd = socket(PF_INET, SOCK_STREAM, 0);
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

int main()
{
	ios::sync_with_stdio(0);

	int registration_socket = OpenListener(REGISTRATION_PORT);
	if (registration_socket == -1)
		exit(0);
	int IRC_socket = OpenListener(IRC_PORT);
	int registration_fd = 0, IRC_fd = 0, flag = 1;
	loadUsers();
	cout << endl;
	pthread_t IRC, registration;
	while (1)
	{
		IRC_fd = accept(IRC_socket, (sockaddr*)NULL, NULL);
		registration_fd = accept(registration_socket, (sockaddr*)NULL, NULL);
		pthread_create(&registration, NULL, registerUser, &registration_fd);
		pthread_create(&IRC, NULL, functionHandler, &IRC_fd);
	}
	close(registration_socket);
	close(IRC_socket);
	return 0;
}