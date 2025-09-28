#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

void whileSleep(long sleepTime) {
    long start = time(NULL);
    long end = start + sleepTime;
    while (time(NULL) < end) {
        struct timeval tv;
        long remainingSecs = end - time(NULL);

        if (remainingSecs <= 0) break;

        tv.tv_sec = (remainingSecs < 1) ? 0 : 1;
        tv.tv_usec = 0;

        select(0, NULL, NULL, NULL, &tv);
  
    }

};

int main() {
    printf("Dummy PID: %d\n", (int)getpid());
    while(1) {
        whileSleep((long)1);
        
    }

    return 0;

}