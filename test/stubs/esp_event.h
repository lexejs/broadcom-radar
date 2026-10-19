#pragma once
#include "esp_wifi.h"
inline int esp_event_loop_create_default() { return mock::call("event_loop"); }
