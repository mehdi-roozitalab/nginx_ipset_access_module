/********************************************************************
 * A nginx module that help you control access of users using IPSET
 * Author: Mohammad Mahdi Roozitalab <mehdiboss_qi@hotmail.com>
 ********************************************************************/

#include <pthread.h>
#include <sys/socket.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <libipset/session.h>
#include <libipset/types.h>

#if __GNUC__
#   define NGX_LIKELY(x)       __builtin_expect(!!(x), 1)
#   define NGX_UNLIKELY(x)     __builtin_expect(!!(x), 0)
#else
#   define NGX_LIKELY(x)        (x)
#   define NGX_UNLIKELY(x)      (x)
#endif

/** IPSET integration ***********************************************/
typedef struct ipset_session        ngx_ipset_session_t;
typedef enum ngx_ipset_test_result_t {
    IPS_TEST_IS_IN_SET,
    IPS_TEST_IS_NOT_IN_SET,
    IPS_TEST_INVALID_SETNAME,
    IPS_TEST_INVALID_IP,
    IPS_TEST_FAIL,
} ngx_ipset_test_result_t;
/** Initialize IPSET.
 * \return 0 to indicate success and other value to indicate error */
static int ngx_initialize_ipset() {
    ipset_load_types();
    return 0;
}
/** Create a new IPSET session. */
static ngx_ipset_session_t* ngx_create_ipset_session() {
#ifdef WITH_LIBIPSET_V6_COMPAT
#   define ngx_ipset_session_new()  ipset_session_init(printf)
#else
#   define ngx_ipset_session_new()  ipset_session_init(NULL, NULL)
#endif
    return ngx_ipset_session_new();
#undef ngx_ipset_session_new
}
/** Destroy an IPSET session that created using \ref ngx_create_ipset_session */
static void ngx_destroy_ipset_session(void* session) {
    if (NGX_UNLIKELY(!session)) {
        return;
    }

    ipset_session_fini(session);
}
static ngx_ipset_test_result_t ngx_test_ip_is_in_set(
    ngx_ipset_session_t* session,
    char const* set,
    char const* ip) {
    int ret;
    const struct ipset_type* type;

    ret = ipset_parse_setname(session, IPSET_SETNAME, set);
    if (NGX_UNLIKELY(ret < 0)) {
        return IPS_TEST_INVALID_SETNAME;
    }

    type = ipset_type_get(session, IPSET_CMD_TEST);
    if (!type) {
        return IPS_TEST_FAIL;
    }

    ret = ipset_parse_elem(session, type->last_elem_optional, ip);
    if (NGX_UNLIKELY(ret < 0)) {
        return IPS_TEST_INVALID_IP;
    }

    ret = ipset_cmd(session, IPSET_CMD_TEST, 0);
    if (ret < 0) {
        return IPS_TEST_IS_NOT_IN_SET;
    }

    return IPS_TEST_IS_IN_SET;
}
/********************************************************************/

/** IPSET session caching *******************************************
 * In order to minimize overhead of the application we will cache IPSET
 * sessions in per thread storage.
 ********************************************************************/
static pthread_key_t ngx_ipset_cache_key;
static int ngx_ipset_cache_initialize_result = 0;
static pthread_once_t ngx_ipset_cache_initialize_once = PTHREAD_ONCE_INIT;
static void ngx_ipset_cache_initializer() {
    ngx_ipset_cache_initialize_result = ngx_initialize_ipset();
    if (ngx_ipset_cache_initialize_result) {
        return;
    }

    if (pthread_key_create(&ngx_ipset_cache_key, ngx_destroy_ipset_session)) {
        ngx_ipset_cache_initialize_result = ngx_errno;
    }
}
static int ngx_initialize_ipset_cache() {
    pthread_once(&ngx_ipset_cache_initialize_once, &ngx_ipset_cache_initializer);
    return ngx_ipset_cache_initialize_result;
}
static ngx_ipset_session_t* ngx_get_session() {
    ngx_ipset_session_t* session;
    int ret = ngx_initialize_ipset_cache();
    if (NGX_UNLIKELY(ret)) {
        ngx_set_errno(ret);
        return NULL;
    }

    session = pthread_getspecific(ngx_ipset_cache_key);
    if (NGX_LIKELY(session)) {
        return session;
    }

    session = ngx_create_ipset_session();
    if (NGX_UNLIKELY(!session)) {
        return NULL;
    }

    pthread_setspecific(ngx_ipset_cache_key, session);
    return session;
}
/********************************************************************/

/** Configuration ***************************************************/
typedef struct ngx_ipset_command_conf_s {
    enum {
        e_mode_not_configured = 0,
        e_mode_off,
        e_mode_blacklist,
        e_mode_whitelist
    } mode;
    ngx_array_t sets;
} ngx_ipset_access_server_conf_t;

static int ngx_str_copy(ngx_pool_t* pool, ngx_str_t* dst, ngx_str_t const* src) {
    if (NGX_UNLIKELY(dst->len >= src->len)) {
        memcpy(dst->data, src->data, src->len);
        dst->len = src->len;
        return 0;
    } else {
        if (NGX_UNLIKELY(dst->data)) {
            ngx_pfree(pool, dst->data);
        }
        dst->data = ngx_pcalloc(pool, src->len + 1);
        if (!dst->data) {
            dst->len = 0;
            return ENOMEM;
        }
        memcpy(dst->data, src->data, src->len);
        dst->data[src->len] = 0;
        dst->len = src->len;
        return 0;
    }
}
static int ngx_str_array_copy(ngx_pool_t* pool, ngx_array_t* dst, ngx_uint_t di, ngx_array_t const* src, ngx_uint_t si) {
    ngx_uint_t i;
    ngx_str_t* dst_values;
    ngx_str_t const* src_values;
    if ((dst->nelts - di) > (dst->size - si)) {
        if (!ngx_array_push_n(dst, dst->nelts - dst->size)) {
            return ENOMEM;
        }
    }
    src_values = src->elts + si;
    dst_values = dst->elts + di;
    for (i = si; i < src->nelts; i++) {
        int ret = ngx_str_copy(pool, dst_values++, src_values++);
        if (ret) {
            return ret;
        }
    }
    return 0;
}

static void* ngx_ipset_access_server_conf_create(ngx_conf_t *cf) {
    ngx_ipset_access_server_conf_t* conf = ngx_pcalloc(cf->pool, sizeof(ngx_ipset_access_server_conf_t));
    return conf;
}
static char* ngx_ipset_access_server_conf_merge(ngx_conf_t* cf, void* parent,  void* child) {
    ngx_ipset_access_server_conf_t* prev = parent;
    ngx_ipset_access_server_conf_t* conf = child;

    if (conf->mode == e_mode_not_configured) {
        // configuration is not configured here, so lets copy it from the parent
        conf->mode = prev->mode;
        if (prev->sets.nelts) {
            if (ngx_str_array_copy(cf->pool, &conf->sets, 0, &prev->sets, 0)) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}
static char* ngx_ipset_access_server_conf_parse(ngx_conf_t* cf, ngx_command_t* command, void* pv_conf) {
    ngx_uint_t i;
    ngx_str_t* values;
    ngx_ipset_session_t* session;
    ngx_str_t* args = cf->args->elts;
    ngx_ipset_access_server_conf_t* conf = pv_conf;

    // first arg is name of the command, and rest of them are values for that command
    if (args[1].len == 3 && memcmp(args[1].data, "off", 3) == 0) {
        conf->mode = e_mode_off;
        return NGX_OK;
    }

    if (ngx_array_init(&conf->sets, cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t))) {
        // error in allocating buffer
        return NGX_ERROR;
    }

    if (ngx_str_array_copy(cf->pool, &conf->sets, 0, cf->args, 1)) {
        return NGX_ERROR;
    }

    conf->mode = args[0].data[0] == 'b' ? e_mode_blacklist : e_mode_whitelist;

    // test input sets
    values = conf->sets.elts;
    session = ngx_get_session();
    if (!session) {
        // failed to create session
        return NGX_ERROR;
    }

    for (i = 0; i < conf->sets.nelts; i++, values++) {
        ngx_ipset_test_result_t result = ngx_test_ip_is_in_set(session, (const char*)values->data, "127.0.0.1");
        if (result == IPS_TEST_FAIL || result == IPS_TEST_INVALID_SETNAME) {
            // error in testing IP in set
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
/********************************************************************/

/** Forward declarations ********************************************/
static ngx_int_t ngx_ipset_access_http_access_handler(ngx_http_request_t* request);
/********************************************************************/

/** NGINX HTTP module ***********************************************/
#define IPSET_ACCESS_COMMAND(name)  {                                   \
    /* name   */ ngx_string(name),                                      \
    /*** configurable per virtual server and in main config       ***/  \
    /*** we require at list one set, but we support more than one ***/  \
    /* type   */ NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,   \
    /* set    */ ngx_ipset_access_server_conf_parse,                    \
    /* conf   */ NGX_HTTP_SRV_CONF_OFFSET,                              \
    /* offset */ 0,                                                     \
    /* post   */ NULL                                                   \
}
static ngx_command_t ngx_http_ipset_access_commands[] = {
    IPSET_ACCESS_COMMAND("blacklist"),
    IPSET_ACCESS_COMMAND("whitelist"),
    ngx_null_command
};

#define checked_array_push(arr, elem) { h = ngx_array_push(&arr); if (h == NULL){ return NGX_ERROR;} *h = elem; }
static ngx_int_t ngx_ipset_access_install_handlers(ngx_conf_t *cf) {
    ngx_http_handler_pt*       h;
    ngx_http_core_main_conf_t* cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    checked_array_push(cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers, ngx_ipset_access_http_access_handler);
}

static ngx_http_module_t ngx_http_ipset_access_module_context = {
    NULL,                                   /* preconfiguration */
    ngx_ipset_access_install_handlers,      /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* merge main configuration */

    ngx_ipset_access_server_conf_create,    /* create server configuration */
    ngx_ipset_access_server_conf_merge,     /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};
ngx_module_t ngx_http_ipset_access = {
    NGX_MODULE_V1,
    &ngx_http_ipset_access_module_context,  /* module context */
    &ngx_http_ipset_access_commands,        /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};
/********************************************************************/

/** implementations *************************************************/
static ngx_int_t ngx_ipset_access_http_access_handler(ngx_http_request_t* request) {
    ngx_ipset_access_server_conf_t  *conf = ngx_http_get_module_srv_conf(request, ngx_http_ipset_access);

    if ((conf->mode == e_mode_whitelist || conf->mode == e_mode_blacklist) &&
        request->connection->sockaddr->sa_family == AF_INET) {
        char* ip;
        ngx_ipset_session_t* session;
        ngx_ipset_test_result_t result;

        ip = inet_ntoa(((struct sockaddr_in*) request->connection->sockaddr)->sin_addr);
        session = ngx_get_session();
        if (!session) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "failed to load an IPSET session");
            result = IPS_TEST_FAIL;
        } else {
            ngx_uint_t i;
            ngx_str_t* sets = conf->sets.elts;
            for (i = 0; i < conf->sets.nelts; i++, sets++) {
                result = ngx_test_ip_is_in_set(session, (char*)sets->data, ip);
                if (result != IPS_TEST_IS_NOT_IN_SET) {
                    if (result == IPS_TEST_FAIL) {
                        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "Failed to test presence of IP in IPSET.");
                    }
                    break;
                }
            }
        }

        if ((conf->mode == e_mode_whitelist && (result != IPS_TEST_IS_IN_SET)) ||
            (conf->mode == e_mode_blacklist && (result == IPS_TEST_IS_NOT_IN_SET))) {
            
            request->keepalive = 0;

            //return a non-standard status when blacklisting
            if(conf->mode == e_mode_blacklist) {
                return 444;
            }
            return NGX_HTTP_FORBIDDEN;        
        }

        return NGX_OK;  
    }

    return NGX_DECLINED;
}
/********************************************************************/