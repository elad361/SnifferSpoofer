#include <unistd.h>

#include <stdlib.h>

#include <stdio.h>

#include <time.h>

#include <sys/time.h>

#include <signal.h>

#include <stdbool.h>

#include <string.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <netinet/tcp.h>

#include <errno.h>

// socket related info
#define IP "127.0.0.1"
#define PORT 3333
#define OPENCONNECTIONS 1
#define OK "okmessage"

//int echo_reply_recv = 0; // is Reply Received?
char buffer[BUFSIZ] = {'\0'};
int server_socket = 0, client_socket = 0;

void no_reply_signal()
{
    printf("\nserver %s cannot not be reached.\n", buffer);
    kill(getppid(), SIGUSR1); // send sig to the parent
    close(server_socket);
    close(client_socket);
    exit(EXIT_SUCCESS);
}

int main()
{
    int er = 1;
    struct sockaddr_in server_address, client_address;
    struct itimerval timer;
    char exitMsg[] = "**EXIT**";

    // set addresses, timer by their struct size
    memset( & server_address, 0, sizeof(server_address));
    memset( & client_address, 0, sizeof(client_address));
    memset( & timer, 0, sizeof(timer));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = inet_addr(IP);
    
    socklen_t address_size = 0;
    char buff[BUFSIZ] = {0};
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    // checking if socket was created successfully
    if (server_socket <= 0) {
        perror("socket creation failed");
        close(server_socket);
        exit(errno);
    }

    // are IP and port reusable? (setsockopt)
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, & er, sizeof(er)) == -1 ) {
        perror("socket is not usab func failed");
        close(server_socket);
        exit(errno);
    }



    if (bind(server_socket, (struct sockaddr * ) & server_address, sizeof(server_address)) ==  -1)
    {
        perror("bind func failed");
        close(server_socket);
        exit(errno);
    }
    
    if (listen(server_socket, OPENCONNECTIONS) < 0) //listen to incoming connections
    {
        perror("listen func failed");
        close(server_socket);
        exit(errno);
    }

    address_size = sizeof(client_address);
    client_socket = accept(server_socket, (struct sockaddr * ) & client_address, & address_size); //accept a new connection from the server socket
    if (client_socket <= 0) // checking
    {
        perror("accept func failed");
        close(client_socket);
        close(server_socket);
        exit(errno);
    }

    signal(SIGALRM, no_reply_signal); // use the no_reply_signal function to check the echo_reply_recv flag

    // timer relevant vars
    timer.it_value.tv_sec = 10;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 10;
    timer.it_interval.tv_usec = 0;

    while (1)
    {
        memset(buffer, 0, BUFSIZ);
        if (recv(client_socket, buffer, BUFSIZ, 0) == -1 ) // receiving IP failure ( no bytes received )
        {
            perror("recv func failed");
            close(client_socket);
            close(server_socket);
            exit(errno);
        }
        if (strcmp(buffer, exitMsg) == 0)
        {
            close(client_socket);
            close(server_socket);
            exit(EXIT_SUCCESS);
        }
        //set a new timer
        timer.it_value.tv_sec = 10;
        timer.it_value.tv_usec = 0;
        timer.it_interval.tv_sec = 10;
        timer.it_interval.tv_usec = 0;
        setitimer(ITIMER_REAL, &timer, NULL); // setting up and running the 10 sec timer

        memset(buffer, 0, BUFSIZ);
        if (recv(client_socket, buffer, BUFSIZ, 0) == -1 ) // receiving IP failure ( no bytes received )
        {
            perror("recv func failed");
            close(client_socket);
            close(server_socket);
            exit(errno);
        }
        //reset the timer
        timer.it_value.tv_sec = 0;
        timer.it_value.tv_usec = 0;
        timer.it_interval.tv_sec = 0;
        timer.it_interval.tv_usec = 0;
        setitimer(ITIMER_REAL, &timer, NULL); // setting up and running the 10 sec timer

        if (strcmp(buffer, exitMsg) == 0)
        {
            close(client_socket);
            close(server_socket);
            exit(EXIT_SUCCESS);
        }
    }
}