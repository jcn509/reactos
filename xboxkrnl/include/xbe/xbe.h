#pragma once
#include <ntoskrnl.h>
#include <reactos/buildno.h>
#include "inbv/logo.h"

#include <stdint.h>

#define NDEBUG
#include <debug.h>

void LoadInitialXbe(PUNICODE_STRING SmssName);