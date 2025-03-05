#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <stdbool.h>

static bool end = false;
int retval = -1;
const char C_FILEPATH [] = "/var/tmp/aesdsocketdata";

void* get_in_addr(struct sockaddr_storage* sa)
{
    if (((struct sockaddr*) sa)->sa_family == AF_INET) {
        return &(((struct sockaddr_in*) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

void signal_handler(int signal)
{
    syslog(LOG_INFO, "Caught signal, exiting");
    end = true;
    retval = 0;
}


int main(int argc, char** argv)
{
    FILE* fp = NULL;
    int new_fd = -1;
    int listenFd = -1;

    openlog ("aesdsocket", 0, LOG_USER);

    for (;;)
    {
        struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_flags = AI_PASSIVE,
        };

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        struct addrinfo* servinfo;


        retval = getaddrinfo(NULL, "9000", &hints, &servinfo);
        if (retval != 0) {
            syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(retval));
            retval = -1;
            break;
        }

        for (struct addrinfo* p = servinfo; p != NULL; p = p->ai_next)
        {
            syslog(LOG_INFO, "Attempt to bind");
            listenFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (listenFd == -1)
            {
                syslog (LOG_ERR, "server: socket: %s", gai_strerror(retval));
                continue;
            }

            int yes = 1;
            if (setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
                syslog (LOG_ERR, "sock flag issue");
                break;
            }

            retval = bind(listenFd, p->ai_addr, p->ai_addrlen);
            if (retval == -1)
            {
                close(listenFd);
                syslog (LOG_ERR, "server: bind: %s", gai_strerror(retval));
                break;
            }

            retval = 0;
            break;
        }

        freeaddrinfo(servinfo);

        if (retval != 0)
        {
            break;
        }

        if (argc > 1)
        {
            int pid = fork();
            if (pid == -1)
            {
                syslog (LOG_ERR, "Fork issue");
                exit(-1);
            }
            else if (pid == 0)
            {
                syslog (LOG_INFO, "Child Process launched");
            }
            else
            {
                // We are done with parent process
                return 0;
            }
        }

        // We binded successfully and now we need to fork

        if (listen(listenFd, 10) == -1) {
            perror("listen");
            exit(-1);
        }

        struct sigaction sa = {
            .sa_handler = signal_handler,
        };

        sigemptyset(&sa.sa_mask);

        if (retval != 0)
        {
            break;
        }

        if (sigaction(SIGINT, &sa, NULL) == -1)
        {
            syslog(LOG_ERR, "sigaction");
            break;
        }

        if (sigaction(SIGTERM, &sa, NULL) == -1)
        {
            syslog(LOG_ERR, "sigaction");
            break;
        }

        fp = fopen(C_FILEPATH, "a+");
        if (fp == NULL)
        {
            syslog(LOG_ERR, "Failed to open file");
            break;
        }


        struct sockaddr_storage their_addr;
        socklen_t sinSize = sizeof(their_addr);
        char strIp[INET6_ADDRSTRLEN] = {0};


        while(!end)
        {
            new_fd = accept(listenFd, (struct sockaddr *)&their_addr, &sinSize);
            if (new_fd == -1) {
                syslog(LOG_ERR, "Accept issue");
                break;
            }

            inet_ntop(their_addr.ss_family,
                get_in_addr(&their_addr),
                strIp, sizeof(strIp));

            syslog(LOG_INFO, "Accepted connection from %s", strIp);
            char buf[1024] = {0};

            while(!end)
            {
                int numbytes = recv(new_fd, buf, sizeof(buf) - 1, 0);

                if (end)
                {
                    break;
                }

                if (numbytes == -1)
                {
                    syslog(LOG_ERR, "recvfrom error %d", numbytes);
                    continue;
                }
                buf[numbytes] = '\0';

                if (fwrite(buf, sizeof(char), numbytes, fp) != numbytes)
                {
                    syslog(LOG_ERR, "Failed to write to file");
                    break;
                }

                printf("Got %d ", numbytes);
                if (buf[numbytes - 1] == '\n')
                {
                    fflush(fp);
                    memset(buf, 0, sizeof(buf));
                    fseek(fp, 0, SEEK_SET);
                    break;
                }
            }

            printf("now we send back\n");
            int numbytes = 1;
            while (numbytes > 0)
            {
                numbytes = fread(buf, sizeof(char), sizeof(buf), fp);
                printf("now we send back %d\n", numbytes);

                // Send the data back
                if (send(new_fd, buf, numbytes, 0) == -1)
                {
                    syslog(LOG_ERR, "send error");
                    break;
                }
            }

            syslog(LOG_INFO, "Closed connection from %s", strIp);
        }

        break;
    }

    if (fp != NULL)
    {
        fclose(fp);
    }

    if (end)
    {
        if (remove(C_FILEPATH) != 0) {
            syslog(LOG_ERR, "Failed to remove file");
        }
    }
    close(listenFd);
    close(new_fd);

    closelog();
    return retval;
}
