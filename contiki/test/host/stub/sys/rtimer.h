/* host-test stand-in: no real-time clock needed on the host */
#pragma once
typedef unsigned long rtimer_clock_t;
#define RTIMER_NOW() 0UL
