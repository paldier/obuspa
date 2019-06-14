/*
 * vendor_iopsys.h: Header file for vendor added definations
 *
 * Copyright (C) 2019 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: vivek.dutta@iopsys.eu
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/**
 * \file vendor_iopsys.h
 *
 * Header file containing defines controlling the build of USP Agent,
 * which is added by vendor
 *
 */
#ifndef VENDOR_IOPSYS_H
#define VENDOR_IOPSYS_H
#include "usp_log.h"

int iopsys_dm_Init(void);
int uspd_operate_sync(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args);

#endif // VENDOR_IOPSYS_H

