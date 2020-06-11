/*
 *
 * Copyright (C) 2019, IOPSYS Software Solutions AB.
 *
 * Author: vivek.dutta@iopsys.eu
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file vendor_uspd.h
 *
 * Header file containing defines controlling the build of USP Agent,
 * which is added by IOPSYS
 *
 */
#ifndef VENDOR_USPD_H
#define VENDOR_USPD_H
#include "vendor_defs.h"
#include "usp_api.h"
#include "str_vector.h"


struct vendor_get_param {
	int fault;
	kv_vector_t kv_vec;
};

struct vendor_add_arg {
	int fault;
	int instance;
};

int vendor_factory_reset_init();
int vendor_reset_init();

void vendor_async_db_init();
void vendor_async_db_clean();
int uspd_resolve_operate_path(char *path, str_vector_t *sv);
int uspd_resolve_path(char *path, str_vector_t *sv);
int uspd_operate_exec(char *path, char *command_key, kv_vector_t *input, kv_vector_t *output, int *instance);

void vendor_get_arg_init(struct vendor_get_param *vget);
int uspd_get_path_value(char *path, struct vendor_get_param *vget);
int uspd_get_instances(char *path, str_vector_t *str_vec);

int uspd_set_path_value(char *path, char *value, int *fault);

int uspd_add_object(char *path, struct vendor_add_arg *vadd);
int uspd_del_object(char *path);

int uspd_get_uniq_kv(char *obj_path, kv_vector_t *params);
#endif // VENDOR_USPD_H

