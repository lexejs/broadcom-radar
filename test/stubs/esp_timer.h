#pragma once
#include "esp_wifi.h"
inline int64_t esp_timer_get_time() { return mock::nowUs; }
