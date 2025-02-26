#include "threading.h"
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

// Helper function to sleep the specified ms using clock_nanosleep. Returns clock_nanosleep error code
int msleep(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    return clock_nanosleep(1, 0, &ts, NULL);
}

void* threadfunc(void* thread_param)
{
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    DEBUG_LOG("Thread %d: waiting %d ms to obtain mutex", thread_func_args->thread_id, thread_func_args->wait_to_obtain_ms);
    msleep(thread_func_args->wait_to_obtain_ms* 1) ;


    DEBUG_LOG("Thread %d: obtained mutex", thread_func_args->thread_id);
    thread_func_args->retval = pthread_mutex_lock(thread_func_args->mutex);
    if (thread_func_args->retval == 0)
    {
        DEBUG_LOG("Thread %d: obtained mutex", thread_func_args->thread_id);
        DEBUG_LOG("Thread %d: waiting %d ms to release mutex", thread_func_args->thread_id, thread_func_args->wait_to_release_ms);
        msleep(thread_func_args->wait_to_release_ms* 1);

        thread_func_args->retval = pthread_mutex_unlock(thread_func_args->mutex);
        if (thread_func_args->retval == 0)
        {
            DEBUG_LOG("Thread %d: released mutex", thread_func_args->thread_id);
            thread_func_args->thread_complete_success = true;
        }
        else
        {
            ERROR_LOG("Thread %d: failed to release mutex", thread_func_args->thread_id);
            thread_func_args->thread_complete_success = false;
        }
    }
    else
    {
        ERROR_LOG("Thread %d: failed to obtain mutex", thread_func_args->thread_id);
        thread_func_args->thread_complete_success = false;
    }


    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    static int thread_id = 0;
    struct thread_data* data = malloc(sizeof(struct thread_data));
    data->thread_id = thread_id++;
    data->wait_to_obtain_ms = wait_to_obtain_ms;
    data->wait_to_release_ms = wait_to_release_ms;
    data->thread_complete_success = true;
    data->mutex = mutex;


    if (pthread_create(thread, NULL, threadfunc, data) != 0)
    {
        ERROR_LOG("Failed to create thread %d", data->thread_id);
        free(data);
        return false;
    }

    return true;

}

