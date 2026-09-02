/**
 * @file filter.c
 * @brief SSH Proxy Core - Filter Chain Implementation
 */

#include "filter.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>

/* Filter chain structure */
struct filter_chain {
    filter_t *head; /* First filter in chain */
    filter_t *tail; /* Last filter in chain */
    size_t count;   /* Number of filters */
};

/* Filter type names */
static const char *filter_type_names[] = {"AUTH", "RBAC", "AUDIT", "RATE_LIMIT", "CUSTOM"};

filter_chain_t *filter_chain_create(void) {
    filter_chain_t *chain = calloc(1, sizeof(filter_chain_t));
    if (chain == NULL) {
        return NULL;
    }
    
    chain->head = NULL;
    chain->tail = NULL;
    chain->count = 0;

    LOG_DEBUG("Filter chain created");
    return chain;
}

void filter_chain_destroy(filter_chain_t *chain) {
    if (chain == NULL) {
        return;
    }

    filter_t *filter = chain->head;
    while (filter != NULL) {
        filter_t *next = filter->next;

        /* Call destroy callback first - it may free config/state */
        if (filter->callbacks.destroy != NULL) {
            filter->callbacks.destroy(filter);
        }

        /* Only free config/state if not already freed by destroy callback */
        /* Note: destroy callbacks should set these to NULL after freeing */
        /* For safety, we no longer free config/state here - destroy callback owns them */
        
        free(filter);

        filter = next;
    }

    free(chain);
    LOG_DEBUG("Filter chain destroyed");
}

int filter_chain_add(filter_chain_t *chain, filter_t *filter) {
    if (chain == NULL || filter == NULL) {
        return -1;
    }

    filter->next = NULL;

    if (chain->tail == NULL) {
        chain->head = filter;
        chain->tail = filter;
    } else {
        chain->tail->next = filter;
        chain->tail = filter;
    }

    chain->count++;

    LOG_DEBUG("Filter '%s' (%s) added to chain, count=%zu", filter->name,
              filter_type_name(filter->type), chain->count);

    return 0;
}

int filter_chain_remove(filter_chain_t *chain, const char *name) {
    if (chain == NULL || name == NULL) {
        return -1;
    }

    filter_t *prev = NULL;
    filter_t *filter = chain->head;

    while (filter != NULL) {
        if (strcmp(filter->name, name) == 0) {
            /* Found it - remove from chain */
            if (prev == NULL) {
                chain->head = filter->next;
            } else {
                prev->next = filter->next;
            }

            if (filter == chain->tail) {
                chain->tail = prev;
            }

            chain->count--;

            /* Cleanup filter */
            if (filter->callbacks.destroy != NULL) {
                filter->callbacks.destroy(filter);
            }
            if (filter->config != NULL) {
                free(filter->config);
            }
            if (filter->state != NULL) {
                free(filter->state);
            }
            free(filter);

            LOG_DEBUG("Filter '%s' removed from chain", name);
            return 0;
        }

        prev = filter;
        filter = filter->next;
    }

    return -1;
}

filter_t *filter_chain_get(filter_chain_t *chain, const char *name) {
    if (chain == NULL || name == NULL) {
        return NULL;
    }

    filter_t *filter = chain->head;
    while (filter != NULL) {
        if (strcmp(filter->name, name) == 0) {
            return filter;
        }
        filter = filter->next;
    }

    return NULL;
}

size_t filter_chain_count(const filter_chain_t *chain) {
    if (chain == NULL) {
        return 0;
    }
    return chain->count;
}

/* Filter chain processing functions */

filter_status_t filter_chain_on_connect(filter_chain_t *chain, filter_context_t *ctx) {
    if (chain == NULL || ctx == NULL) {
        return FILTER_REJECT;
    }

    filter_t *filter = chain->head;
    while (filter != NULL) {
        if (filter->callbacks.on_connect != NULL) {
            filter_status_t status = filter->callbacks.on_connect(filter, ctx);
            if (status != FILTER_CONTINUE) {
                LOG_DEBUG("Filter '%s' returned %d on connect", filter->name, status);
                return status;
            }
        }
        filter = filter->next;
    }

    return FILTER_CONTINUE;
}

filter_status_t filter_chain_on_auth(filter_chain_t *chain, filter_context_t *ctx) {
    if (chain == NULL || ctx == NULL) {
        return FILTER_REJECT;
    }

    filter_t *filter = chain->head;
    while (filter != NULL) {
        if (filter->callbacks.on_auth != NULL) {
            filter_status_t status = filter->callbacks.on_auth(filter, ctx);
            if (status != FILTER_CONTINUE) {
                LOG_DEBUG("Filter '%s' returned %d on auth", filter->name, status);
                return status;
            }
        }
        filter = filter->next;
    }

    return FILTER_CONTINUE;
}

filter_status_t filter_chain_on_authenticated(filter_chain_t *chain, filter_context_t *ctx) {
    if (chain == NULL || ctx == NULL) {
        return FILTER_REJECT;
    }

    filter_t *filter = chain->head;
    while (filter != NULL) {
        if (filter->callbacks.on_authenticated != NULL) {
            filter_status_t status = filter->callbacks.on_authenticated(filter, ctx);
            if (status != FILTER_CONTINUE) {
                LOG_DEBUG("Filter '%s' returned %d on authenticated", filter->name, status);
                return status;
            }
        }
        filter = filter->next;
    }

    return FILTER_CONTINUE;
}

filter_status_t filter_chain_on_route(filter_chain_t *chain, filter_context_t *ctx) {
    if (chain == NULL || ctx == NULL) {
        return FILTER_REJECT;
    }

    filter_t *filter = chain->head;
    while (filter != NULL) {
        if (filter->callbacks.on_route != NULL) {
            filter_status_t status = filter->callbacks.on_route(filter, ctx);
            if (status != FILTER_CONTINUE) {
                LOG_DEBUG("Filter '%s' returned %d on route", filter->name, status);
                return status;
            }
        }
        filter = filter->next;
    }

    return FILTER_CONTINUE;
}

filter_status_t filter_chain_on_data_upstream(filter_chain_t *chain, filter_context_t *ctx,
                                              const uint8_t *data, size_t len) {
    if (chain == NULL || ctx == NULL) {
        return FILTER_REJECT;
    }

    filter_t *filter = chain->head;
    while (filter != NULL) {
        if (filter->callbacks.on_data_upstream != NULL) {
            filter_status_t status = filter->callbacks.on_data_upstream(filter, ctx, data, len);
            if (status != FILTER_CONTINUE) {
                return status;
            }
        }
        filter = filter->next;
    }

    return FILTER_CONTINUE;
}

filter_status_t filter_chain_on_data_downstream(filter_chain_t *chain, filter_context_t *ctx,
                                                const uint8_t *data, size_t len) {
    if (chain == NULL || ctx == NULL) {
        return FILTER_REJECT;
    }

    filter_t *filter = chain->head;
    while (filter != NULL) {
        if (filter->callbacks.on_data_downstream != NULL) {
            filter_status_t status = filter->callbacks.on_data_downstream(filter, ctx, data, len);
            if (status != FILTER_CONTINUE) {
                return status;
            }
        }
        filter = filter->next;
    }

    return FILTER_CONTINUE;
}

void filter_chain_on_close(filter_chain_t *chain, filter_context_t *ctx) {
    if (chain == NULL || ctx == NULL) {
        return;
    }

    filter_t *filter = chain->head;
    while (filter != NULL) {
        if (filter->callbacks.on_close != NULL) {
            filter->callbacks.on_close(filter, ctx);
        }
        filter = filter->next;
    }
}

filter_t *filter_create(const char *name, filter_type_t type, const filter_callbacks_t *callbacks,
                        void *config) {
    if (name == NULL || callbacks == NULL) {
        return NULL;
    }

    filter_t *filter = calloc(1, sizeof(filter_t));
    if (filter == NULL) {
        return NULL;
    }

    filter->name = name;
    filter->type = type;
    filter->callbacks = *callbacks;
    filter->config = config;
    filter->state = NULL;
    filter->next = NULL;

    return filter;
}

const char *filter_type_name(filter_type_t type) {
    if (type >= 0 && type <= FILTER_TYPE_CUSTOM) {
        return filter_type_names[type];
    }
    return "UNKNOWN";
}
