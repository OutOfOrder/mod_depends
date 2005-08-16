/* Copyright 2004 Paul Querna
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"       
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_md5.h"

#include "apr_strings.h"
#include "apr_md5.h"

#include "mod_depends.h"

module AP_MODULE_DECLARE_DATA depends_module;

static ap_filter_rec_t *depends_filter_handle;

typedef struct depends_conf 
{
    apr_array_header_t* files;
    apr_md5_ctx_t md5ctx;
} depends_conf;

typedef struct md_info 
{
    char* path;
} md_info;

static depends_conf* build_config(request_rec* r) 
{
    depends_conf* conf;

    conf = apr_palloc(r->pool, sizeof(depends_conf));

    conf->files = apr_array_make(r->pool, 3, sizeof(md_info*));

    apr_md5_init(&conf->md5ctx);

    ap_set_module_config(r->request_config, &depends_module, conf);

    ap_add_output_filter_handle(depends_filter_handle, NULL, r, r->connection);

    return conf;
}

APR_DECLARE(apr_status_t) depends_add_hash(request_rec* r, const char* data,
                          apr_size_t len)
{
    depends_conf* conf = ap_get_module_config(r->request_config, 
                                              &depends_module);
    if(!conf) {
        conf = build_config(r);
    }

    apr_md5_update(&conf->md5ctx, data, len);

    return APR_SUCCESS;
}

APR_DECLARE(apr_status_t) depends_add_file(request_rec* r, const char* path)
{
    md_info* fp;
    depends_conf* conf = ap_get_module_config(r->request_config, 
                                              &depends_module);
    if(!conf) {
        conf = build_config(r);
    }

    fp = apr_array_push(conf->files);
    fp->path = apr_pstrdup(r->pool, path);

    return APR_SUCCESS;
}

static int depends_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    md_info *fp;
    apr_status_t rv;
    char *etag;

    depends_conf* conf = ap_get_module_config(f->r->request_config, 
                                              &depends_module);
    if(!conf) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }
    
    while((fp = apr_array_pop(conf->files)) != NULL) {
        apr_finfo_t finfo;

        rv = apr_stat(&finfo, fp->path,
                      APR_FINFO_MTIME|APR_FINFO_INODE|APR_FINFO_SIZE, 
                      f->r->pool);

        if(rv != APR_SUCCESS) {
            continue;
        }

        apr_md5_update(&conf->md5ctx, &finfo.inode, sizeof(finfo.inode));
        apr_md5_update(&conf->md5ctx, &finfo.size, sizeof(finfo.size));
        apr_md5_update(&conf->md5ctx, &finfo.mtime, sizeof(finfo.mtime));

        ap_update_mtime(f->r, finfo.mtime);
    }

    etag = ap_md5contextTo64(f->r->pool, &conf->md5ctx);

    apr_table_setn(f->r->headers_out, "ETag", etag);
    ap_set_last_modified(f->r);

    ap_set_module_config(f->r->request_config, &depends_module, NULL);
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static const command_rec depends_cmds[] = {
    {NULL}
};

static void depends_hooks(apr_pool_t * p) 
{
    APR_REGISTER_OPTIONAL_FN(depends_add_hash);
    APR_REGISTER_OPTIONAL_FN(depends_add_file);
    /* Must run before the Cache Save Filters */
    depends_filter_handle = ap_register_output_filter("DEPENDS_HACK", 
                              depends_filter, NULL,
                              AP_FTYPE_CONTENT_SET-2);

}

module AP_MODULE_DECLARE_DATA depends_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    depends_cmds,
    depends_hooks
};
