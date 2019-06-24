/*
 * vendor_operate_async.c: vendor implementaion of async operate commands
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

#include <stdio.h>
#include <time.h>
#include <string.h>

#include <libubus.h>
#include <libubox/blobmsg_json.h>

#include "common_defs.h"
#include "usp_api.h"
#include "dm_access.h"
#include "os_utils.h"
#include "json.h"
#include "vendor_iopsys.h"


#define WIFI_NDIAG "Device.WiFi.NeighboringWiFiDiagnostic"
#define VENDOR_CONF "Device.DeviceInfo.VendorConfigFile."

typedef struct
{
    int request_instance;   // Instance number of this operation in the Device.LocalAgent.Request table
	char path[MAX_DM_PATH];
	kv_vector_t *input_args;
} input_cond_t;

typedef struct
{
    char result_str[MAX_DM_VALUE_LEN*4];
    char err_msg[256];
} output_res_t;

static char *selftest_output_args[] =
{
    "Result.",
};

static char *backup_input_args[] =
{
    "URL",
	"Username",
	"Password"
};

static char *restore_input_args[] =
{
    "URL",
	"Username",
	"Password",
	"FileSize",
	"TargetFileName",
	"CheckSumAlgorithm",
	"CheckSum"
};


static void receive_print(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char *str;
	if (!msg)
		return;

	str = blobmsg_format_json_indent(msg, true, -1);
	USP_LOG_Debug("%s", str);
	strncpy(req->priv, str, MAX_DM_VALUE_LEN*4);
	free(str);
}

int ExecuteTestDiagnostic(char *cpath, kv_vector_t *input_args, output_res_t *res)
{
	uint32_t id;
	struct blob_buf b = { };
	kv_pair_t *kv;
	char path[MAX_DM_PATH] = {'\0'}, action[MAX_DM_PATH] = {'\0'};
	char *last_delim = strrchr(cpath, '.');

	struct ubus_context *ctx = ubus_connect(NULL);
	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	strcpy(action, last_delim+1);
	strncpy(path, cpath, abs(last_delim - cpath)+1);

	if (!ctx) {
		USP_LOG_Error("[%s:%d] ubus_connect failed",__func__, __LINE__);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (ubus_lookup_id(ctx, USP_UBUS, &id)) {
		USP_LOG_Error("[%s:%d] %s not present",__func__, __LINE__, USP_UBUS);
		return USP_ERR_INTERNAL_ERROR;
	}

	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "action", action);
	if(input_args->num_entries) {
		void *table = blobmsg_open_table(&b, "input");
		for(int i=0; i<input_args->num_entries; ++i) {
			kv = &input_args->vector[i];
			USP_LOG_Info("[%s:%d] INPUT key |%s| value|%s|",__func__, __LINE__, kv->key, kv->value);
			blobmsg_add_string(&b, kv->key, kv->value);
		}
		blobmsg_close_table(&b, table);
	}

	if (ubus_invoke(ctx, id, "operate", b.head, receive_print, res->result_str, 10000)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, path);
		return USP_ERR_INTERNAL_ERROR;
	}

	ubus_free(ctx);
	return USP_ERR_OK;
}

void *wifiTestDiagThreadMain(void *param)
{
    input_cond_t *cond = (input_cond_t *) param;
    output_res_t results;
    output_res_t *res = &results;
    kv_vector_t *output_args;
    char *err_msg;
    int err = USP_ERR_OK;

    memset(&results, 0, sizeof(results));

    // Exit if unable to signal that this operation is active
    err = USP_SIGNAL_OperationStatus(cond->request_instance, "Active");
    if (err == USP_ERR_OK)
    {
		// Perform the self test diagnostic
		err = ExecuteTestDiagnostic(cond->path, cond->input_args, res);
    }
	else
	{
        USP_SNPRINTF(res->err_msg, sizeof(res->err_msg), "%s: USP_SIGNAL_OperationStatus() failed", __FUNCTION__);
	}

    // Log output results
    USP_LOG_Info("=== NeighboringWiFiDiagnostic completed with result=%d ===", err);
    // Save all results into the output arguments using KV_VECTOR_ functions
    output_args = USP_MALLOC(sizeof(kv_vector_t));
    KV_VECTOR_Init(output_args);

	JsonNode *json, *jr;
	if((json = json_decode(res->result_str)) == NULL) {
    	USP_LOG_Error("Decoding of json failed");
		return NULL;
	}
	if((jr = json_find_member(json, "Result.")) != NULL) {
		char *encoded_result = json_encode(jr);
    	KV_VECTOR_Add(output_args, "Result.", encoded_result);
		json_delete(jr);
	}

    // Inform the protocol handler, that the operation has completed
    // Ownership of the output args passes to protocol handler
    err_msg = (err != USP_ERR_OK) ? res->err_msg : NULL;
    USP_SIGNAL_OperationComplete(cond->request_instance, err, err_msg, output_args);

    // Free the input conditions
	json_delete(json);
    USP_FREE(cond);

    return NULL;
}

void *vendorConfigThreadMain(void *param)
{
    input_cond_t *cond = (input_cond_t *) param;
    output_res_t results;
    output_res_t *res = &results;
    char *err_msg;
    int err = USP_ERR_OK;

    memset(&results, 0, sizeof(results));

    // Exit if unable to signal that this operation is active
    err = USP_SIGNAL_OperationStatus(cond->request_instance, "Active");
    if (err == USP_ERR_OK)
    {
		// Perform the self test diagnostic
		err = ExecuteTestDiagnostic(cond->path, cond->input_args, res);
    }
	else
	{
        USP_SNPRINTF(res->err_msg, sizeof(res->err_msg), "%s: USP_SIGNAL_OperationStatus() failed", __FUNCTION__);
	}

    // Log output results
    USP_LOG_Info("=== Vendorconfig completed with result=%d ===", err);
    USP_LOG_Info("Result: %s", res->result_str);

    // Inform the protocol handler, that the operation has completed
    // Ownership of the output args passes to protocol handler
    err_msg = (err != USP_ERR_OK) ? res->err_msg : NULL;
    USP_SIGNAL_OperationComplete(cond->request_instance, err, err_msg, NULL);

    // Free the input conditions
    USP_FREE(cond);

    return NULL;
}

int async_operate_handler(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int err = USP_ERR_OK;
    input_cond_t *cond;

    // Allocate input conditions to pass to thread
    cond = USP_MALLOC(sizeof(input_cond_t));
    memset(cond, 0, sizeof(input_cond_t));
    cond->request_instance = instance;
	strcpy(cond->path, req->path);

	cond->input_args = (kv_vector_t *) malloc(sizeof(kv_vector_t));
	KV_VECTOR_Init(cond->input_args);

	if(input_args->num_entries) {
		for(int i=0; i<input_args->num_entries; ++i) {
			kv_pair_t *kv = &input_args->vector[i];
			USP_LOG_Info("[%s:%d] INPUT key |%s| value|%s|",__func__, __LINE__, kv->key, kv->value);
			KV_VECTOR_Add(cond->input_args, kv->key, kv->value);
		}
	}

    // Log the input conditions for the operation
    USP_LOG_Info("=== Conditions ===");
    USP_LOG_Info("instance_number: %d", cond->request_instance);
	KV_VECTOR_Dump(input_args);
    USP_LOG_Info("req path: %s", cond->path);

    // Exit if unable to start a thread to perform this operation
    // NOTE: ownership of input conditions passes to the thread
	if(0 == strncmp(cond->path, WIFI_NDIAG, sizeof(WIFI_NDIAG))) {
		err = OS_UTILS_CreateThread(wifiTestDiagThreadMain, cond);
	} else {
		err = OS_UTILS_CreateThread(vendorConfigThreadMain, cond);
	}
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_COMMAND_FAILURE;
    }

    // Ownership of the input conditions has passed to the thread
    return err;
}

int wifi_NeighboringWiFiDiagnostics_Init(void)
{
    int err = USP_ERR_OK;

    // Register self test diagnostics
    err |= USP_REGISTER_AsyncOperation("Device.WiFi.NeighboringWiFiDiagnostic()", async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.WiFi.NeighboringWiFiDiagnostic()", NULL, 0, selftest_output_args, NUM_ELEM(selftest_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int vendorConfig_backup_Init(void)
{
    int err = USP_ERR_OK;

    // Register self test diagnostics
    err |= USP_REGISTER_AsyncOperation("Device.DeviceInfo.VendorConfigFile.{i}.Backup()", async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DeviceInfo.VendorConfigFile.{i}.Backup()", backup_input_args, NUM_ELEM(backup_input_args), NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int vendorConfig_restore_Init(void)
{
    int err = USP_ERR_OK;

    // Register self test diagnostics
    err |= USP_REGISTER_AsyncOperation("Device.DeviceInfo.VendorConfigFile.{i}.Restore()", async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DeviceInfo.VendorConfigFile.{i}.Restore()", restore_input_args, NUM_ELEM(restore_input_args), NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int vendor_operate_async_init(void)
{
	int err = USP_ERR_OK;

	err |= wifi_NeighboringWiFiDiagnostics_Init();
	err |= vendorConfig_backup_Init();
	err |= vendorConfig_restore_Init();

	return err;
}
