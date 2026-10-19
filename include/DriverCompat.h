#pragma once
#include "WpsProbe.h"
#if RADAR_DRIVER_COMPAT
namespace radar {
struct CompatTxResult { int error = 0, stockError = 0; bool applied = false, observed = false; };
CompatTxResult transmitCompatible(const Frame& frame, const WpsProbe& probe);
}
#endif
