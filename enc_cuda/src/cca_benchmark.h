#pragma once

#define STR(s) #s
#if defined(__x86_64__) || defined(_M_X64)
#define CCA_MARKER(marker)
#else
#define CCA_MARKER(marker) __asm__ volatile("MOV XZR, " STR(marker))
#endif

#define CCA_MARKER_CPU_ENC CCA_MARKER(0x80)
#define CCA_MARKER_CPU_DEC CCA_MARKER(0x81)
#define CCA_MARKER_GPU_ENC_KERNEL CCA_MARKER(0x82)