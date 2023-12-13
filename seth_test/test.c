#include <stdio.h>
#include <time.h>
#include <stdlib.h>


static inline void timespec_diff(struct timespec *start, struct timespec *end, struct timespec *result) {
    result->tv_sec  = end->tv_sec  - start->tv_sec;
    result->tv_nsec = end->tv_nsec - start->tv_nsec;
    if (result->tv_nsec < 0) {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}


int main() {
        struct timespec start, end, result;
        // int iterations = 2000000;
        int iterations = 5000;
        int *result_vec = malloc(sizeof(int) * iterations);

        // // Warmup the cache
        // for (int i = 0; i < 1000; i++) {
        //         clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	//         clock_gettime(CLOCK_MONOTONIC_RAW, &end);
        //         timespec_diff(&start, &end, &result);
        // }

        // Get results
        for (int i = 0; i < iterations; i++) {
                clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	        clock_gettime(CLOCK_MONOTONIC_RAW, &end);
                timespec_diff(&start, &end, &result);
                result_vec[i] = result.tv_nsec;
        }


    	FILE* fptr;
        fptr = fopen("results.txt", "w");
        for (int i = 0; i < iterations; i++) {
                fprintf(fptr, "%d\n", result_vec[i]);
        }
        fclose(fptr);

        return 0;
}