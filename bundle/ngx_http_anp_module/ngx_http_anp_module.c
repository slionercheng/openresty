/*
 * Copyright (C) 2025 OpenResty Developer
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Module configuration structure */
typedef struct {
    ngx_flag_t  enable;  /* Module enable flag */
} ngx_http_anp_loc_conf_t;

/* Function declarations */
static ngx_int_t ngx_http_anp_handler(ngx_http_request_t *r);
static void *ngx_http_anp_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_anp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_anp_init(ngx_conf_t *cf);

/* Module directive */
static ngx_command_t ngx_http_anp_commands[] = {
    { 
        ngx_string("anp"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_anp_loc_conf_t, enable),
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

    return conf;
}

/* Merge location configuration */
static char *
ngx_http_anp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_anp_loc_conf_t *prev = parent;
    ngx_http_anp_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}

/* Handler function - this is where the main logic of the module resides */
static ngx_int_t
ngx_http_anp_handler(ngx_http_request_t *r)
{
    ngx_http_anp_loc_conf_t  *alcf;
    ngx_str_t                 method;
    ngx_str_t                 uri;
    ngx_str_t                 protocol;
    ngx_str_t                 host;
    ngx_uint_t                i;
    ngx_table_elt_t          *header;
    ngx_log_t                *log;
    ngx_list_part_t          *part;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_anp_module);
    log = r->connection->log;

    if (!alcf->enable) {
        return NGX_DECLINED;
    }

    /* Log request information */
    ngx_log_error(NGX_LOG_INFO, log, 0, "ANP module processing request");

    /* Get HTTP method */
    method.len = r->method_name.len;
    method.data = r->method_name.data;
    ngx_log_error(NGX_LOG_INFO, log, 0, "ANP: Method: %V", &method);

    /* Get URI */
    uri.len = r->uri.len;
    uri.data = r->uri.data;
    ngx_log_error(NGX_LOG_INFO, log, 0, "ANP: URI: %V", &uri);

    /* Get HTTP protocol version */
    if (r->http_protocol.len) {
        protocol.len = r->http_protocol.len;
        protocol.data = r->http_protocol.data;
        ngx_log_error(NGX_LOG_INFO, log, 0, "ANP: Protocol: %V", &protocol);
    }

    /* Get Host header */
    if (r->headers_in.host) {
        host.len = r->headers_in.host->value.len;
        host.data = r->headers_in.host->value.data;
        ngx_log_error(NGX_LOG_INFO, log, 0, "ANP: Host: %V", &host);
    }

    /* Log all headers */
    ngx_log_error(NGX_LOG_INFO, log, 0, "ANP: Headers:");
    
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        ngx_log_error(NGX_LOG_INFO, log, 0, "ANP: Header: %V: %V",
                      &header[i].key, &header[i].value);
    }

    /* 
     * Here you would implement your ANP protocol processing logic
     * For example, you might want to:
     * 1. Parse specific headers
     * 2. Validate the request against ANP protocol rules
     * 3. Modify the request or prepare data for later phases
     */

    /* For demonstration, let's add a custom header to the response */
    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        return NGX_ERROR;
    }

    header->hash = 1;
    ngx_str_set(&header->key, "X-ANP-Processed");
    ngx_str_set(&header->value, "true");

    /* 
     * Return NGX_OK to allow the request to continue to the next phase
     * If you want to block the request based on ANP logic, you could return:
     * - NGX_HTTP_FORBIDDEN
     * - NGX_HTTP_BAD_REQUEST
     * - or any other appropriate HTTP status code
     */
    return NGX_OK;
}

/* Module initialization */
static ngx_int_t
ngx_http_anp_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* Register our handler at the access phase */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_anp_handler;

    return NGX_OK;
}
