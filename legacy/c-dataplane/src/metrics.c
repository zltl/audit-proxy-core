/**
 * @file metrics.c
 * @brief Runtime metrics singleton
 */

#include "metrics.h"
#include <string.h>

static metrics_t g_metrics;

void metrics_init(void)
{
    memset(&g_metrics, 0, sizeof(g_metrics));
    g_metrics.start_time = time(NULL);
}

metrics_t *metrics_get(void)
{
    return &g_metrics;
}
