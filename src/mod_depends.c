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

#include "apr_strings.h"

#include "mod_depends.h"

module AP_MODULE_DECLARE_DATA depends_module;

static ap_filter_rec_t *depends_filter_handle;

typedef struct md_info 
{
    char* path;
} md_info;

APR_DECLARE(apr_status_t) depends_add_file(request_rec* r, const char* path)
{
    md_info* fp;
    apr_array_header_t* conf = ap_get_module_config(r->request_config, 
                                             &depends_module);
    if(!conf) {
        conf = apr_array_make(r->pool, 3, sizeof(md_info*));
        ap_set_module_config(r->request_config, &depends_module, conf);
        ap_add_output_filter_handle(depends_filter_handle, NULL, r, r->connection);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "add file: %s", path);

    fp = apr_array_push(conf);
    fp->path = apr_pstrdup(r->pool, path);

    return APR_SUCCESS;
}

static const command_rec depends_cmds[] = {
    {NULL}
};

#define ETAG_WEAK "W/"
#define CHARS_PER_UNSIGNED_LONG (sizeof(unsigned long) * 2)

/* Generate the human-readable hex representation of an unsigned long
 * (basically a faster version of 'sprintf("%lx")')
 */
#define HEX_DIGITS "0123456789abcdef"
static char *etag_ulong_to_hex(char *next, unsigned long u)
{
    int printing = 0;
    int shift = sizeof(unsigned long) * 8 - 4;
    do {
        unsigned long next_digit = ((u >> shift) & (unsigned long)0xf);
        if (next_digit) {
            *next++ = HEX_DIGITS[next_digit];
            printing = 1;
        }
        else if (printing) {
            *next++ = HEX_DIGITS[next_digit];
        }
        shift -= 4;
    } while (shift);
    *next++ = HEX_DIGITS[u & (unsigned long)0xf];
    return next;
}

static int depends_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    md_info *fp;
    apr_status_t rv;
    char *etag;
    char *next;

    apr_array_header_t* conf = ap_get_module_config(f->r->request_config, 
                                             &depends_module);
    if(!conf) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }
    
    etag = apr_palloc(f->r->pool, sizeof("\"\"") +
                      conf->nelts * ( sizeof("--") + (3 * CHARS_PER_UNSIGNED_LONG + 1)));
    next = etag;

    *next++ = '"';

    while((fp = apr_array_pop(conf)) != NULL) {
        apr_finfo_t *finfo;

        rv = apr_stat(finfo, fp->path, APR_FINFO_MTIME|APR_FINFO_INODE|APR_FINFO_SIZE, f->r->pool);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, f->r,
                  "stat file: %s", fp->path);

        if(rv != APR_SUCCESS)
            continue;

        next = etag_ulong_to_hex(next, (unsigned long)finfo->inode);
        *next++ = '-';
        next = etag_ulong_to_hex(next, (unsigned long)finfo->size);
        *next++ = '-';
        next = etag_ulong_to_hex(next, (unsigned long)finfo->mtime);
        ap_update_mtime(f->r, finfo->mtime);
    }
    *next++ = '"';
    *next = '\0';

    apr_table_setn(f->r->headers_out, "ETag", etag);
    ap_set_last_modified(f->r);

    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static void depends_hooks(apr_pool_t * p) 
{
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
