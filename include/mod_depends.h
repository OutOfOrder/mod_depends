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

#ifndef _MOD_DEPENDS_H
#define _MOD_DEPENDS_H

#include <httpd.h>
#include <apr_optional.h>

#ifdef __cplusplus
extern "C" {
#endif

APR_DECLARE_OPTIONAL_FN(apr_status_t, depends_add_file,
                        (request_rec *r, const char* path));

APR_DECLARE_OPTIONAL_FN(apr_status_t, depends_add_hash,
                        (request_rec *r, const char* data, apr_size_t len));

APR_DECLARE(apr_status_t) depends_add_file(request_rec* r, const char* path);
APR_DECLARE(apr_status_t) depends_add_hash(request_rec* r, const char* data, 
                          apr_size_t len);

#ifdef __cplusplus
}  
#endif

#endif /* _MOD_DEPENDS_H */

