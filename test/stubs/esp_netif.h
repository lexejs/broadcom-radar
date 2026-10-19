#pragma once
#include "esp_wifi.h"
inline int esp_netif_init() { return mock::call("netif_init"); }
