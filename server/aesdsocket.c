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
#include <pthread.h>
#include <time.h>
#include <sys/queue.h>

static volatile bool end = false;
int retval = -1;
const char C_FILEPATH[] = "/var/tmp/aesdsocketdata";
const char C_PORT[] = "9000";
const int C_CONNECTION_REQUEST_QUEUE_SIZE = 10;
pthread_mutex_t lock;
FILE *fp = NULL;
timer_t timerid;

typedef struct thread_info
{
    pthread_t thread_id;
    int thread_num;
    char strIp[INET6_ADDRSTRLEN];
    int socketId;
    FILE *fd;
    pthread_mutex_t *lock;
} thread_info;

struct slist_data
{
    thread_info *data;
    SLIST_ENTRY(slist_data)
    entries;
};

/**
 * Return the IP Address of the client depending if it is ipv4 or ipv6
 * @param sa
 * @return pointer to the ip address array. Valid until sa is valid
 */
void *get_in_addr(struct sockaddr_storage *sa)
{
    if (((struct sockaddr *)sa)->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

/**
 * Callback function to handle a specific signal
 * @param signal signal caught
 */
void signal_handler(int signal)
{
    printf("Signal\n");

    syslog(LOG_INFO, "Caught signal, exiting");
    end = true;
    retval = 0;
}

/**
 * Callback function to handle a specific signal
 * @param signal signal caught
 */
void signal_timer_handler(int signal)
{
    time_t rawtime;
    time(&rawtime);
    struct tm *timeinfo = localtime(&rawtime);

    char prefix[] = "timestamp:";
    if (fp != NULL)
    {
        pthread_mutex_lock(&lock);
         fwrite(prefix, sizeof(char), strlen(prefix), fp);
         fwrite(asctime(timeinfo), sizeof(char), strlen(asctime(timeinfo)), fp);
         fflush(fp);
        pthread_mutex_unlock(&lock);
    }

    printf("Timer expired\n");

    syslog(LOG_INFO, "timer");
}

static void *thread_handler(void *arg)
{

    thread_info *tinfo = (thread_info *)arg;

    syslog(LOG_INFO, "Accepted connection from %s", tinfo->strIp);
    char buf[1024] = {0};

    pthread_mutex_lock(tinfo->lock);

    // Get the current position of the file
    long current = 0;
    // ftell(tinfo->fd);

    while (!end)
    {
        int numbytes = recv(tinfo->socketId, buf, sizeof(buf) - 1, 0);

        if (numbytes == -1)
        {
            syslog(LOG_ERR, "recvfrom error %d", numbytes);
            continue;
        }
        buf[numbytes] = '\0';

        if (fwrite(buf, sizeof(char), numbytes, tinfo->fd) != numbytes)
        {
            syslog(LOG_ERR, "Failed to write to file");
            break;
        }

        printf("Got a total of %d\n", numbytes);
        if (buf[numbytes - 1] == '\n')
        {
            fflush(tinfo->fd);
            memset(buf, 0, sizeof(buf));
            fseek(tinfo->fd, current, SEEK_SET);
            break;
        }
    }

    // Read back the file and send it through the socket
    int numbytes = 1;
    while (numbytes > 0)
    {
        numbytes = fread(buf, sizeof(char), sizeof(buf), tinfo->fd);
        if (numbytes == 0)
        {
            // There is nothing to send
            break;
        }

        // Send the data back
        if (send(tinfo->socketId, buf, numbytes, 0) == -1)
        {
            syslog(LOG_ERR, "send error");
            break;
        }
    }

    syslog(LOG_INFO, "Closed connection from %s", tinfo->strIp);

    pthread_mutex_unlock(tinfo->lock);

    return NULL;
}

void maskTimer(int signal, bool stop)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, signal);

    if (stop)
    {
        if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1)
        {
            return;
        }
    }
    else
    {
        if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
        {
            return;
        }
    }
}

void timer_start(void)
{
    struct sigevent sev;
    struct sigaction sa;

    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    sev.sigev_value.sival_ptr = &timerid;

    sa.sa_flags = SA_SIGINFO;
    sa.sa_handler = signal_timer_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sev.sigev_signo, &sa, NULL) == -1)
    {
        return;
    }

    maskTimer(sev.sigev_signo, true);

    if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1)
    {
        return;
    }

    struct itimerspec its = {0};
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(timerid, 0, &its, NULL) == -1)
    {
        return;
    }

    maskTimer(sev.sigev_signo, false);
}

int main(int argc, char **argv)
{
    int new_fd = -1;
    int listenFd = -1;

    openlog("aesdsocket", 0, LOG_USER);

    SLIST_HEAD(slisthead, slist_data)
    head = SLIST_HEAD_INITIALIZER(head);
    SLIST_INIT(&head);

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
        struct addrinfo *servinfo;

        retval = getaddrinfo(NULL, C_PORT, &hints, &servinfo);
        if (retval != 0)
        {
            syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(retval));
            retval = -1;
            break;
        }

        for (struct addrinfo *p = servinfo; p != NULL; p = p->ai_next)
        {
            syslog(LOG_INFO, "Attempt to bind");
            listenFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (listenFd == -1)
            {
                syslog(LOG_ERR, "server: socket: %s", gai_strerror(retval));
                // Try to find other address
                continue;
            }

            // Enable reusable address
            const int reuseAddr = 1;
            retval = setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr));
            if (retval == -1)
            {
                syslog(LOG_ERR, "sock flag issue");
                break;
            }

            retval = bind(listenFd, p->ai_addr, p->ai_addrlen);
            if (retval == -1)
            {
                close(listenFd);
                syslog(LOG_ERR, "server: bind: %s", gai_strerror(retval));
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
                syslog(LOG_ERR, "Fork issue");
                exit(-1);
            }
            else if (pid == 0)
            {
                syslog(LOG_INFO, "Child Process launched");
            }
            else
            {
                // We are done with parent process
                return 0;
            }
        }

        if (listen(listenFd, C_CONNECTION_REQUEST_QUEUE_SIZE) == -1)
        {
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

        if ((sigaction(SIGINT, &sa, NULL) == -1) ||
            (sigaction(SIGTERM, &sa, NULL) == -1))
        {
            syslog(LOG_ERR, "sigaction");
            break;
        }

        if (pthread_mutex_init(&lock, NULL) != 0)
        {
            syslog(LOG_ERR, "mutex init issue");
            return 1;
        }

        fp = fopen(C_FILEPATH, "a+");
        if (fp == NULL)
        {
            syslog(LOG_ERR, "Failed to open file");
            break;
        }

        timer_start();

        int id = 0;
        while (!end)
        {
            socklen_t sinSize = sizeof(struct sockaddr_storage);
            struct sockaddr_storage their_addr = {0};

            // For some reasons, the accept call hangs when the timer expires
            // So we need to check if the timer expired and break the loop

            new_fd = accept(listenFd, (struct sockaddr *)&their_addr, &sinSize);
            if (new_fd == -1)
            {
                if (errno == EINTR && !end)
                {
                    continue;
                }
                syslog(LOG_ERR, "Accept issue %d", errno);
                break;
            }

            thread_info *tinfo = (thread_info *)malloc(sizeof(thread_info));
            if (tinfo == NULL)
            {
                syslog(LOG_ERR, "Failed to allocate memory");
                break;
            }

            inet_ntop(their_addr.ss_family,
                      get_in_addr(&their_addr), tinfo->strIp, sizeof(tinfo->strIp));
            tinfo->thread_num = id++;
            tinfo->socketId = new_fd;
            tinfo->fd = fp;
            tinfo->lock = &lock;
            // And now we spawn a thread for handling this connection

            retval = pthread_create(&tinfo->thread_id, NULL, &thread_handler, tinfo);
            if (retval != 0)
            {
                syslog(LOG_ERR, "Thread create issue");
                break;
            }

            struct slist_data *item = (struct slist_data *)malloc(sizeof(struct slist_data));
            if (item == NULL)
            {
                syslog(LOG_ERR, "Failed to allocate memory");
                break;
            }

            item->data = tinfo;
            SLIST_INSERT_HEAD(&head, item, entries);
        }

        break;
    }

    // Free the item in the queue
    struct slist_data *item;
    while (!SLIST_EMPTY(&head))
    {
        item = SLIST_FIRST(&head);
        SLIST_REMOVE_HEAD(&head, entries);
        pthread_join(item->data->thread_id, NULL);
        free(item->data);
        free(item);
    }

    struct itimerspec its = {0};
    if (timer_settime(timerid, 0, &its, NULL) == -1)
    {
        syslog(LOG_ERR, "Failed to set timer");
    }

    if (fp != NULL)
    {
        fclose(fp);
    }

    if (end)
    {
        if (remove(C_FILEPATH) != 0)
        {
            syslog(LOG_ERR, "Failed to remove file");
        }
    }
    if (listenFd != -1)
    {
        close(listenFd);
    }

    if (new_fd != -1)
    {
        close(new_fd);
    }

    pthread_mutex_destroy(&lock);
    timer_delete(timerid);
    closelog();
    return retval;
}
