#pragma once

#define STR(s) #s
#define CCA_MARKER(marker) __asm__ volatile("MOV XZR, " STR(marker))

#define CCA_MARKER_CPU_ENC CCA_MARKER(0x80)
#define CCA_MARKER_CPU_DEC CCA_MARKER(0x81)
#define CCA_MARKER_GPU_ENC_KERNEL CCA_MARKER(0x82)