#pragma once
#include "FreeRTOS.h"
#include <cstring>
struct StaticQueue_t { uint8_t* storage = nullptr; size_t depth = 0, itemSize = 0, count = 0, next = 0; };
using QueueHandle_t = StaticQueue_t*;
inline QueueHandle_t xQueueCreateStatic(size_t depth, size_t size, uint8_t* data, StaticQueue_t* control) {
    *control = {data, depth, size, 0, 0}; return control;
}
inline int xQueueSend(QueueHandle_t q, const void* item, int wait) {
    if (wait != 0 || q->count == q->depth) return 0;
    std::memcpy(q->storage + ((q->next + q->count) % q->depth) * q->itemSize, item, q->itemSize); ++q->count; return pdTRUE;
}
inline int xQueueReceive(QueueHandle_t q, void* item, int wait) {
    if (wait != 0 || !q->count) return 0;
    std::memcpy(item, q->storage + q->next * q->itemSize, q->itemSize); q->next = (q->next + 1) % q->depth; --q->count; return pdTRUE;
}
inline unsigned uxQueueMessagesWaiting(QueueHandle_t q) { return unsigned(q->count); }
inline void xQueueReset(QueueHandle_t q) { q->count = q->next = 0; }
