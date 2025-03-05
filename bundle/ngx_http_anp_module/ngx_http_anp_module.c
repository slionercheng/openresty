/*
 * Copyright (C) 2025 OpenResty Developer
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <time.h>


/* DID permission configuration */
typedef struct {
    ngx_array_t *allowed_dids;  /* Array of ngx_str_t for allowed DIDs */
    ngx_flag_t   allow_all;      /* Flag to allow all DIDs */
    ngx_str_t    blacklist_key;  /* Redis key for blacklist */
} ngx_http_anp_did_perms_t;

/* Module configuration structure */
/* Shared memory configuration */
typedef struct {
    ngx_int_t   size;      /* Size of shared memory zone */
} ngx_http_anp_shm_conf_t;

typedef struct {
    ngx_flag_t  enable;  /* Module enable flag */
    ngx_int_t   timestamp_window;  /* Allowed timestamp window in seconds */
    ngx_http_anp_did_perms_t did_perms;  /* DID permissions */
    ngx_http_anp_shm_conf_t shm;  /* Shared memory configuration */
    ngx_int_t   nonce_timeout;  /* Nonce expiration time in seconds */
} ngx_http_anp_loc_conf_t;

/* Shared memory data structure */
typedef struct {
    ngx_slab_pool_t      *shpool;         /* Shared memory pool */
    ngx_rbtree_t          nonce_rbtree;     /* Red-black tree for nonce storage */
    ngx_rbtree_node_t     nonce_sentinel;   /* Sentinel node for nonce rbtree */
    ngx_queue_t           nonce_queue;      /* Queue for nonce expiration */
    
    ngx_rbtree_t          blacklist_rbtree; /* Red-black tree for blacklist storage */
    ngx_rbtree_node_t     blacklist_sentinel; /* Sentinel node for blacklist rbtree */
} ngx_http_anp_shm_t;

/* Nonce node structure */
typedef struct {
    ngx_rbtree_node_t     node;     /* RB tree node */
    ngx_queue_t           queue;    /* Queue node */
    time_t                expires;  /* Expiration time */
    u_char                data[1];  /* Start of nonce string */
} ngx_http_anp_nonce_node_t;

static ngx_http_anp_shm_t *ngx_http_anp_shm_zone_data;

/* DID Authorization header components */
typedef struct {
    ngx_str_t did;
    ngx_str_t nonce;
    ngx_str_t timestamp;
    ngx_str_t verification_method;
    ngx_str_t signature;
} ngx_http_anp_auth_t;


/* Function declarations */
static ngx_int_t ngx_http_anp_handler(ngx_http_request_t *r);
static void *ngx_http_anp_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_anp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_anp_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_anp_parse_auth_header(ngx_http_request_t *r, ngx_http_anp_auth_t *auth);
static ngx_int_t ngx_http_anp_validate_timestamp(ngx_http_request_t *r, ngx_str_t *timestamp, ngx_int_t window);
static ngx_int_t ngx_http_anp_validate_nonce(ngx_http_request_t *r, ngx_str_t *nonce);
static ngx_int_t ngx_http_anp_validate_did_permission(ngx_http_request_t *r, ngx_str_t *did);
static char *ngx_http_anp_allow_did(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
    int err;
    char *errstr;
} redisContext;

typedef struct {
    void * type;
    char *str;
    int integer;
} redisReply;

#define REDIS_REPLY_ERROR -1
#define REDIS_REPLY_NIL 0
#define REDIS_REPLY_STRING 1
#define REDIS_REPLY_ARRAY 2
#define REDIS_REPLY_INTEGER 3
#define REDIS_REPLY_STATUS 4


/* Module directives */


static ngx_int_t
ngx_http_anp_remove_from_blacklist(ngx_http_request_t *r, ngx_str_t *did);

static ngx_int_t
ngx_http_anp_add_to_blacklist(ngx_http_request_t *r, ngx_str_t *did);

/* Handler for blacklist management commands */
static ngx_int_t
ngx_http_anp_manage_blacklist(ngx_http_request_t *r)
{
    ngx_str_t did;
    ngx_int_t rc;
    ngx_table_elt_t *h;
    u_char *p, *last;
    ngx_str_t action;

    /* Only allow POST method */
    if (!(r->method & (NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* Get DID from request body */
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Extract action from URI */
    last = ngx_http_map_uri_to_path(r, &action, NULL, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Get DID from request body */
    p = r->request_body->bufs->buf->pos;
    did.data = p;
    did.len = r->request_body->bufs->buf->last - p;

    /* Remove any trailing whitespace */
    while (did.len > 0 && (did.data[did.len - 1] == '\r' || 
           did.data[did.len - 1] == '\n' || 
           did.data[did.len - 1] == ' ')) {
        did.len--;
    }

    if (did.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Check action and perform accordingly */
    if (ngx_strncmp(action.data, "blacklist", 9) == 0) {
        rc = ngx_http_anp_add_to_blacklist(r, &did);
    } else if (ngx_strncmp(action.data, "unblacklist", 11) == 0) {
        rc = ngx_http_anp_remove_from_blacklist(r, &did);
    } else {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Add success response header */
    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "X-Blacklist-Status");
        ngx_str_set(&h->value, "success");
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;

    return ngx_http_send_header(r);
}

static char *
ngx_http_anp_blacklist_loc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_anp_manage_blacklist;

    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_anp_commands[] = {
    { 
        ngx_string("anp"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_anp_loc_conf_t, enable),
        NULL 
    },
    {
        ngx_string("anp_timestamp_window"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_anp_loc_conf_t, timestamp_window),
        NULL
    },
    {
        ngx_string("anp_allow_did"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_anp_allow_did,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("anp_allow_all_dids"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_anp_loc_conf_t, did_perms.allow_all),
        NULL
    },
    {
        ngx_string("anp_nonce_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_anp_loc_conf_t, nonce_timeout),
        NULL
    },
    {
        ngx_string("anp_blacklist"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_anp_blacklist_loc,
        0,
        0,
        NULL
    },
    ngx_null_command
};

/* Module context */
static ngx_http_module_t ngx_http_anp_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_anp_init,             /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_anp_create_loc_conf,  /* create location configuration */
    ngx_http_anp_merge_loc_conf    /* merge location configuration */
};

/* Module definition */
ngx_module_t ngx_http_anp_module = {
    NGX_MODULE_V1,
    &ngx_http_anp_module_ctx,      /* module context */
    ngx_http_anp_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/* Create location configuration */
static void *
ngx_http_anp_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_anp_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_anp_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->timestamp_window = NGX_CONF_UNSET;
    conf->did_perms.allow_all = NGX_CONF_UNSET;
    conf->did_perms.allowed_dids = NULL;

    /* Initialize shared memory configuration defaults */
    conf->shm.size = NGX_CONF_UNSET;
    conf->nonce_timeout = NGX_CONF_UNSET;

    return conf;
}

/* Merge location configuration */
static char *
ngx_http_anp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_anp_loc_conf_t *prev = parent;
    ngx_http_anp_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->timestamp_window, prev->timestamp_window, 60); /* Default 60 seconds */
    ngx_conf_merge_value(conf->did_perms.allow_all, prev->did_perms.allow_all, 0);

    /* Merge allowed DIDs arrays */
    if (prev->did_perms.allowed_dids && !conf->did_perms.allowed_dids) {
        conf->did_perms.allowed_dids = prev->did_perms.allowed_dids;
    }

    /* Merge shared memory configuration */
    ngx_conf_merge_value(conf->shm.size, prev->shm.size, 2 * 1024 * 1024); /* Default 2MB */
    ngx_conf_merge_value(conf->nonce_timeout, prev->nonce_timeout, 300); /* Default 5 minutes */

    return NGX_CONF_OK;
}

/* Parse DID Authorization header */
static ngx_int_t
ngx_http_anp_parse_auth_header(ngx_http_request_t *r, ngx_http_anp_auth_t *auth)
{
    ngx_str_t auth_header;
    u_char *start, *end, *p;
    
    /* Get Authorization header */
    if (r->headers_in.authorization == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ANP: No Authorization header found");
        return NGX_HTTP_UNAUTHORIZED;
    }
    
    auth_header = r->headers_in.authorization->value;
    
    /* Check if it starts with 'DIDWba' */
    if (auth_header.len < 7 || 
        ngx_strncasecmp(auth_header.data, (u_char *) "DIDWba ", 7) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ANP: Invalid Authorization header format");
        return NGX_HTTP_UNAUTHORIZED;
    }
    
    /* Parse each component */
    p = auth_header.data + 7;
    end = auth_header.data + auth_header.len;
    
    /* Parse did */
    if ((start = ngx_strstr(p, "did=\"")) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    start += 5;
    if ((p = ngx_strchr(start, '"')) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    auth->did.data = start;
    auth->did.len = p - start;
    
    /* Parse nonce */
    if ((start = ngx_strstr(p, "nonce=\"")) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    start += 7;
    if ((p = ngx_strchr(start, '"')) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    auth->nonce.data = start;
    auth->nonce.len = p - start;
    
    /* Parse timestamp */
    if ((start = ngx_strstr(p, "timestamp=\"")) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    start += 11;
    if ((p = ngx_strchr(start, '"')) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    auth->timestamp.data = start;
    auth->timestamp.len = p - start;
    
    /* Parse verification_method */
    if ((start = ngx_strstr(p, "verification_method=\"")) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    start += 20;
    if ((p = ngx_strchr(start, '"')) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    auth->verification_method.data = start;
    auth->verification_method.len = p - start;
    
    /* Parse signature */
    if ((start = ngx_strstr(p, "signature=\"")) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    start += 10;
    if ((p = ngx_strchr(start, '"')) == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }
    auth->signature.data = start;
    auth->signature.len = p - start;
    
    return NGX_OK;
}

/* Validate timestamp */
static ngx_int_t
ngx_http_anp_validate_timestamp(ngx_http_request_t *r, ngx_str_t *timestamp, ngx_int_t window)
{
    time_t current_time, request_time;
    struct tm tm;
    char time_str[32];
    
    /* Convert timestamp string to time_t */
    if (timestamp->len >= sizeof(time_str)) {
        return NGX_ERROR;
    }
    
    ngx_memcpy(time_str, timestamp->data, timestamp->len);
    time_str[timestamp->len] = '\0';
    
    if (strptime(time_str, "%Y-%m-%dT%H:%M:%SZ", &tm) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ANP: Invalid timestamp format");
        return NGX_ERROR;
    }
    
    request_time = timegm(&tm);
    current_time = time(NULL);
    
    /* Check if timestamp is within allowed window */
    if (request_time < current_time - window || 
        request_time > current_time + window) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ANP: Timestamp outside allowed window");
        return NGX_ERROR;
    }
    
    return NGX_OK;
}


/* Validate nonce using shm */
/* Generate a random nonce */
static ngx_str_t
ngx_http_anp_generate_nonce(ngx_http_request_t *r)
{
    ngx_str_t nonce;
    u_char *p;
    int i;

    nonce.len = 32;  /* 32 bytes for nonce */
    nonce.data = ngx_pnalloc(r->pool, nonce.len * 2 + 1);  /* Each byte becomes 2 hex chars */
    if (nonce.data == NULL) {
        nonce.len = 0;
        return nonce;
    }

    p = nonce.data;
    for (i = 0; i < nonce.len; i++) {
        unsigned char random_byte;
        if (RAND_bytes(&random_byte, 1) != 1) {
            nonce.len = 0;
            return nonce;
        }
        *p++ = "0123456789abcdef"[random_byte >> 4];
        *p++ = "0123456789abcdef"[random_byte & 0xf];
    }
    *p = '\0';
    nonce.len = nonce.len * 2;

    return nonce;
}

/* Error codes as defined in 3.2.4.1 */
typedef struct {
    const char *code;
    const char *message;
} ngx_http_anp_error_t;

static ngx_http_anp_error_t ngx_http_anp_errors[] = {
    {"invalid_header", "Authorization header format is invalid"},
    {"invalid_timestamp", "Timestamp is invalid or expired"},
    {"invalid_nonce", "Nonce is invalid or has been used"},
    {"invalid_signature", "Signature verification failed"},
    {"invalid_did", "DID format is invalid or DID document not found"},
    {NULL, NULL}
};

/* Add WWW-Authenticate header with challenge */
static ngx_int_t
ngx_http_anp_add_challenge(ngx_http_request_t *r, const char *error_code)
{
    ngx_table_elt_t *h;
    ngx_str_t nonce;
    u_char *challenge;
    size_t len;
    const char *error_message = NULL;
    ngx_http_anp_error_t *error;

    /* Find error message for the given error code */
    for (error = ngx_http_anp_errors; error->code != NULL; error++) {
        if (ngx_strcmp(error->code, error_code) == 0) {
            error_message = error->message;
            break;
        }
    }

    /* Generate new nonce */
    nonce = ngx_http_anp_generate_nonce(r);
    if (nonce.len == 0) {
        return NGX_ERROR;
    }

    /* Calculate length for challenge string */
    len = sizeof("DID-WBA realm=\"\", nonce=\"\", error=\"\", error_description=\"\"")
          + sizeof("anp-server") + nonce.len 
          + (error_code ? strlen(error_code) : 0)
          + (error_message ? strlen(error_message) : 0);

    challenge = ngx_pnalloc(r->pool, len);
    if (challenge == NULL) {
        return NGX_ERROR;
    }

    /* Format challenge string */
    if (error_code && error_message) {
        ngx_snprintf(challenge, len,
                     "DID-WBA realm=\"anp-server\", nonce=\"%V\", error=\"%s\", error_description=\"%s\"",
                     &nonce, error_code, error_message);
    } else {
        ngx_snprintf(challenge, len,
                     "DID-WBA realm=\"anp-server\", nonce=\"%V\"",
                     &nonce);
    }

    /* Add WWW-Authenticate header */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "WWW-Authenticate");
    h->value.data = challenge;
    h->value.len = ngx_strlen(challenge);

    return NGX_OK;
}

static ngx_int_t
ngx_http_anp_validate_nonce(ngx_http_request_t *r, ngx_str_t *nonce)
{
    ngx_http_anp_loc_conf_t *alcf;
    ngx_http_anp_nonce_node_t *node;
    uint32_t hash;
    ngx_rbtree_node_t *rn;
    ngx_rbtree_key_t key;
    time_t now;
    
    if (nonce->len < 8 || nonce->len > 32) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ANP: Invalid nonce length");
        return NGX_ERROR;
    }

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_anp_module);
    
    /* Calculate hash of nonce */
    hash = ngx_crc32_short(nonce->data, nonce->len);
    key = hash;
    
    /* Lock shared memory */
    ngx_shmtx_lock(&ngx_http_anp_shm_zone_data->shpool->mutex);
    
    /* Check if nonce exists in rbtree */
    rn = ngx_http_anp_shm_zone_data->nonce_rbtree.root;
    while (rn != &ngx_http_anp_shm_zone_data->nonce_sentinel) {
        if (key < rn->key) {
            rn = rn->left;
            continue;
        }
        if (key > rn->key) {
            rn = rn->right;
            continue;
        }
        
        /* Found matching key, check nonce string */
        node = (ngx_http_anp_nonce_node_t *) rn;
        if (nonce->len == ngx_strlen(node->data) &&
            ngx_strncmp(nonce->data, node->data, nonce->len) == 0) {
            ngx_shmtx_unlock(&ngx_http_anp_shm_zone_data->shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ANP: Nonce already used");
            return NGX_ERROR;
        }
        rn = rn->right;
    }
    
    /* Allocate and insert new nonce */
    node = ngx_slab_alloc_locked(ngx_http_anp_shm_zone_data->shpool,
                                sizeof(ngx_http_anp_nonce_node_t) + nonce->len);
    if (node == NULL) {
        ngx_shmtx_unlock(&ngx_http_anp_shm_zone_data->shpool->mutex);
        return NGX_ERROR;
    }
    
    now = ngx_time();
    node->node.key = key;
    node->expires = now + alcf->nonce_timeout;
    ngx_memcpy(node->data, nonce->data, nonce->len);
    
    ngx_rbtree_insert(&ngx_http_anp_shm_zone_data->nonce_rbtree, &node->node);
    ngx_queue_insert_tail(&ngx_http_anp_shm_zone_data->nonce_queue, &node->queue);
    
    /* Clean expired nonces */
    while (!ngx_queue_empty(&ngx_http_anp_shm_zone_data->nonce_queue)) {
        ngx_queue_t *q = ngx_queue_head(&ngx_http_anp_shm_zone_data->nonce_queue);
        node = ngx_queue_data(q, ngx_http_anp_nonce_node_t, queue);
        
        if (node->expires > now) {
            break;
        }
        
        ngx_queue_remove(q);
        ngx_rbtree_delete(&ngx_http_anp_shm_zone_data->nonce_rbtree, &node->node);
        ngx_slab_free_locked(ngx_http_anp_shm_zone_data->shpool, node);
    }
    
    ngx_shmtx_unlock(&ngx_http_anp_shm_zone_data->shpool->mutex);
    return NGX_OK;
}

/* Handler function - this is where the main logic of the module resides */
static ngx_int_t
ngx_http_anp_handler(ngx_http_request_t *r)
{
    ngx_http_anp_loc_conf_t  *alcf;
    ngx_http_anp_auth_t       auth;
    ngx_table_elt_t          *header;
    ngx_int_t                 rc;
    
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_anp_module);
    
    if (!alcf->enable) {
        return NGX_DECLINED;
    }
    
    /* Parse Authorization header */
    rc = ngx_http_anp_parse_auth_header(r, &auth);
    if (rc != NGX_OK) {
        ngx_http_anp_add_challenge(r, "invalid_header");
        return NGX_HTTP_UNAUTHORIZED;
    }
    
    /* Validate timestamp */
    rc = ngx_http_anp_validate_timestamp(r, &auth.timestamp, alcf->timestamp_window);
    if (rc != NGX_OK) {
        ngx_http_anp_add_challenge(r, "invalid_timestamp");
        return NGX_HTTP_UNAUTHORIZED;
    }
    
    /* Validate nonce */
    rc = ngx_http_anp_validate_nonce(r, &auth.nonce);
    if (rc != NGX_OK) {
        ngx_http_anp_add_challenge(r, "invalid_nonce");
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Validate DID permissions */
    rc = ngx_http_anp_validate_did_permission(r, &auth.did);
    if (rc != NGX_OK) {
        /* For 403, we don't include a new challenge since the authentication was successful */
        ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
        if (h != NULL) {
            h->hash = 1;
            ngx_str_set(&h->key, "X-Error-Message");
            ngx_str_set(&h->value, "DID not authorized to access this resource");
        }
        return NGX_HTTP_FORBIDDEN;
    }
    
    /* Add custom header to indicate successful DID authentication */
    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        return NGX_ERROR;
    }
    
    header->hash = 1;
    ngx_str_set(&header->key, "X-DID-Authenticated");
    ngx_str_set(&header->value, "true");

    /* Add the authenticated DID to response headers */
    header = ngx_list_push(&r->headers_out.headers);
    if (header != NULL) {
        header->hash = 1;
        ngx_str_set(&header->key, "X-Authenticated-DID");
        header->value.data = auth.did.data;
        header->value.len = auth.did.len;
    }
    
    return NGX_OK;
}

/* DID permission validation */
/* Check if DID is in blacklist */
static ngx_int_t
ngx_http_anp_check_blacklist(ngx_http_request_t *r, ngx_str_t *did)
{
    uint32_t hash;
    ngx_rbtree_node_t *node;
    ngx_rbtree_key_t key;
    ngx_int_t rc = NGX_OK;
    
    /* Calculate hash of DID */
    hash = ngx_crc32_short(did->data, did->len);
    key = hash;
    
    /* Lock shared memory */
    ngx_shmtx_lock(&ngx_http_anp_shm_zone_data->shpool->mutex);
    
    /* Check if DID exists in blacklist rbtree */
    node = ngx_http_anp_shm_zone_data->blacklist_rbtree.root;
    while (node != &ngx_http_anp_shm_zone_data->blacklist_sentinel) {
        if (key < node->key) {
            node = node->left;
            continue;
        }
        if (key > node->key) {
            node = node->right;
            continue;
        }
        
        /* Found matching key, check DID string */
        if (did->len == ((ngx_str_t *)(node + 1))->len &&
            ngx_strncmp(did->data, ((ngx_str_t *)(node + 1))->data, did->len) == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ANP: DID is blacklisted: %V", did);
            rc = NGX_ERROR;
            break;
        }
        node = node->right;
    }
    
    ngx_shmtx_unlock(&ngx_http_anp_shm_zone_data->shpool->mutex);
    return rc;
}

/* Add DID to blacklist */
static ngx_int_t
ngx_http_anp_add_to_blacklist(ngx_http_request_t *r, ngx_str_t *did)
{
    uint32_t hash;
    ngx_rbtree_node_t *node;
    ngx_rbtree_key_t key;
    ngx_str_t *blacklist_did;
    size_t size;
    
    /* Calculate hash of DID */
    hash = ngx_crc32_short(did->data, did->len);
    key = hash;
    
    /* Lock shared memory */
    ngx_shmtx_lock(&ngx_http_anp_shm_zone_data->shpool->mutex);
    
    /* Check if DID already exists */
    node = ngx_http_anp_shm_zone_data->blacklist_rbtree.root;
    while (node != &ngx_http_anp_shm_zone_data->blacklist_sentinel) {
        if (key < node->key) {
            node = node->left;
            continue;
        }
        if (key > node->key) {
            node = node->right;
            continue;
        }
        
        blacklist_did = (ngx_str_t *)(node + 1);
        if (did->len == blacklist_did->len &&
            ngx_strncmp(did->data, blacklist_did->data, did->len) == 0) {
            ngx_shmtx_unlock(&ngx_http_anp_shm_zone_data->shpool->mutex);
            return NGX_OK; /* Already blacklisted */
        }
        node = node->right;
    }
    
    /* Allocate and insert new blacklist entry */
    size = sizeof(ngx_rbtree_node_t) + sizeof(ngx_str_t) + did->len;
    node = ngx_slab_alloc_locked(ngx_http_anp_shm_zone_data->shpool, size);
    if (node == NULL) {
        ngx_shmtx_unlock(&ngx_http_anp_shm_zone_data->shpool->mutex);
        return NGX_ERROR;
    }
    
    node->key = key;
    
    blacklist_did = (ngx_str_t *)(node + 1);
    blacklist_did->len = did->len;
    blacklist_did->data = (u_char *)blacklist_did + sizeof(ngx_str_t);
    ngx_memcpy(blacklist_did->data, did->data, did->len);
    
    ngx_rbtree_insert(&ngx_http_anp_shm_zone_data->blacklist_rbtree, node);
    
    ngx_shmtx_unlock(&ngx_http_anp_shm_zone_data->shpool->mutex);
    return NGX_OK;
}

/* Remove DID from blacklist */
static ngx_int_t
ngx_http_anp_remove_from_blacklist(ngx_http_request_t *r, ngx_str_t *did)
{
    uint32_t hash;
    ngx_rbtree_node_t *node;
    ngx_rbtree_key_t key;
    ngx_str_t *blacklist_did;
    
    /* Calculate hash of DID */
    hash = ngx_crc32_short(did->data, did->len);
    key = hash;
    
    /* Lock shared memory */
    ngx_shmtx_lock(&ngx_http_anp_shm_zone_data->shpool->mutex);
    
    /* Find and remove DID from blacklist */
    node = ngx_http_anp_shm_zone_data->blacklist_rbtree.root;
    while (node != &ngx_http_anp_shm_zone_data->blacklist_sentinel) {
        if (key < node->key) {
            node = node->left;
            continue;
        }
        if (key > node->key) {
            node = node->right;
            continue;
        }
        
        blacklist_did = (ngx_str_t *)(node + 1);
        if (did->len == blacklist_did->len &&
            ngx_strncmp(did->data, blacklist_did->data, did->len) == 0) {
            ngx_rbtree_delete(&ngx_http_anp_shm_zone_data->blacklist_rbtree, node);
            ngx_slab_free_locked(ngx_http_anp_shm_zone_data->shpool, node);
            ngx_shmtx_unlock(&ngx_http_anp_shm_zone_data->shpool->mutex);
            return NGX_OK;
        }
        node = node->right;
    }
    
    ngx_shmtx_unlock(&ngx_http_anp_shm_zone_data->shpool->mutex);
    return NGX_ERROR; /* DID not found in blacklist */
}

static ngx_int_t
ngx_http_anp_validate_did_permission(ngx_http_request_t *r, ngx_str_t *did)
{
    ngx_http_anp_loc_conf_t *alcf;
    ngx_str_t *allowed_did;
    ngx_uint_t i;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_anp_module);

    /* First check if DID is blacklisted */
    if (ngx_http_anp_check_blacklist(r, did) != NGX_OK) {
        return NGX_ERROR;
    }

    /* If allow_all is enabled and DID is not blacklisted, permit access */
    if (alcf->did_perms.allow_all) {
        return NGX_OK;
    }

    /* If no allowed DIDs are configured and allow_all is false, deny access */
    if (alcf->did_perms.allowed_dids == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ANP: No DID permissions configured");
        return NGX_ERROR;
    }

    /* Check if the DID is in the allowed list */
    allowed_did = alcf->did_perms.allowed_dids->elts;
    for (i = 0; i < alcf->did_perms.allowed_dids->nelts; i++) {
        if (did->len == allowed_did[i].len &&
            ngx_strncmp(did->data, allowed_did[i].data, did->len) == 0) {
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ANP: DID not authorized: %V", did);
    return NGX_ERROR;
}

/* Configuration directive handler for anp_allow_did */
static char *
ngx_http_anp_allow_did(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_anp_loc_conf_t *alcf = conf;
    ngx_str_t *value;
    ngx_str_t *did;

    /* Create array if it doesn't exist */
    if (alcf->did_perms.allowed_dids == NULL) {
        alcf->did_perms.allowed_dids = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (alcf->did_perms.allowed_dids == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    did = ngx_array_push(alcf->did_perms.allowed_dids);
    if (did == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Store the DID string */
    did->data = value[1].data;
    did->len = value[1].len;

    return NGX_CONF_OK;
}

/* Module initialization */
static ngx_int_t
ngx_http_anp_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_anp_shm_t *shm;
    ngx_slab_pool_t *shpool;
    
    if (data) { /* Zone already initialized */
        shm_zone->data = data;
        return NGX_OK;
    }
    
    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    
    /* Lock the shared memory */
    ngx_shmtx_lock(&shpool->mutex);
    
    shm = ngx_slab_alloc(shpool, sizeof(ngx_http_anp_shm_t));
    if (shm == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }
    
    /* Store slab pool pointer */
    shm->shpool = shpool;
    
    /* Initialize nonce red-black tree and queue */
    ngx_rbtree_init(&shm->nonce_rbtree, &shm->nonce_sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&shm->nonce_queue);
    
    /* Initialize blacklist red-black tree */
    ngx_rbtree_init(&shm->blacklist_rbtree, &shm->blacklist_sentinel, ngx_rbtree_insert_value);
    
    shm_zone->data = shm;
    ngx_http_anp_shm_zone_data = shm;
    
    /* Unlock the shared memory */
    ngx_shmtx_unlock(&shpool->mutex);
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_anp_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_str_t                  shm_name = ngx_string("anp_shared");
    ngx_shm_zone_t           *shm_zone;
    
    /* Create shared memory zone for nonce and blacklist storage */
    shm_zone = ngx_shared_memory_add(cf, &shm_name, 20 * 1024 * 1024, /* 20MB */
                                    &ngx_http_anp_module);
    if (shm_zone == NULL) {
        return NGX_ERROR;
    }
    
    shm_zone->init = ngx_http_anp_init_shm_zone;
    shm_zone->data = NULL;
    
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    
    /* Register our handler at the access phase */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    
    *h = ngx_http_anp_handler;
    
    return NGX_OK;
}
