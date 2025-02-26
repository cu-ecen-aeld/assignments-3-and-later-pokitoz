#include <syslog.h>
#include <stdio.h>
#include <errno.h>

int main(int argv, char** args)
{
    int retval = 1;
    openlog("Writer", LOG_PID, LOG_USER);

    if (argv != 3)
    {
        syslog(LOG_ERR, "on arguments");
        retval = 1;
    }
    else
    {
        // we assume the directory is created by the caller.
        // and we assume many of the checks were already done before
        // for security

        FILE* fptr = fopen(args[1],"w");
        if(fptr == NULL)
        {
            syslog(LOG_ERR, "on open %d", errno);
            retval = 1;
        }
        else
        {
            if (fprintf(fptr,"%s", args[2]) < 0)
            {
                syslog(LOG_ERR, "on write %d", errno);
                retval = 1;
            }
            else
            {
                syslog(LOG_DEBUG, "Writing %s to %s", args[2], args[1]);
                retval = 0;
            }

            if (fclose(fptr) != 0)
            {
                syslog(LOG_WARNING, "on close %d", errno);
            }
        }
    }

    closelog();
    return retval;
}