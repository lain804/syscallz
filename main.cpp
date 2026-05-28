#include <cstdio>
#include <Windows.h>

#include "syscallz.hpp"

int main() {
    syscallz::init();

    SIZE_T portNumber = 0;
    {
        NTSTATUS ok = syscallz::syscall<"NtQueryInformationProcess">(
            GetCurrentProcess(),
            ProcessDebugPort,
            &portNumber,
            sizeof(portNumber),
            NULL
        );
        printf("NtQueryInformationProcess status: 0x%X\n", ok);
    }
    printf("Debugger Detected: %s\n", portNumber != 0 ? "true" : "false");

    LARGE_INTEGER start, end ,freq;
    {
        NTSTATUS ok = syscallz::syscall<"NtQueryPerformanceCounter">(
            &start,
            &freq
        );
        printf("NtQueryPerformanceCounter start status: 0x%X\n", ok);
    }

    LARGE_INTEGER interval;
    interval.QuadPart = -10000000LL; // negative meaning relative, 1 second in 100ns units

    // https://ntdoc.m417z.com/ntdelayexecution
    syscallz::syscall<"NtDelayExecution">(FALSE, &interval);
   
    {
        NTSTATUS ok = syscallz::syscall<"NtQueryPerformanceCounter">(
            &end,
            NULL
        );
        printf("NtQueryPerformanceCounter end status: 0x%X\n", ok);
    }

    printf("Time Elapsed: %lfs\n", (double)(end.QuadPart - start.QuadPart) / freq.QuadPart);
}