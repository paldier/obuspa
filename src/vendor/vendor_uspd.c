/*
 *
 * Copyright (C) 2019, IOPSYS Software Solutions AB.
 *
 * Author: vivek.dutta@iopsys.eu
 * Author: y.yashvardhan@iopsys.eu
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "vendor_uspd.h"
#include "os_utils.h"
#include "common_defs.h"
#include "data_model.h"
#include "str_vector.h"
#include "json.h"

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

// Timeout in milliseconds
#define USP_PROTO "usp"
#define USPD_TIMEOUT 5000
#define ASYNC_USPD_TIMEOUT 30000

typedef void (*UBUS_USP_CB) (struct ubus_request *req, int type, struct blob_attr *msg);

typedef struct
{
    // Instance number of this operation in the Device.LocalAgent.Request table
    int request_instance;
    char path[MAX_DM_PATH];
    kv_vector_t *input_args;
} input_cond_t;

static str_vector_t gs_async_paths;

static int uspd_operate_sync(dm_req_t *req, __unused char *command_key,
			     kv_vector_t *input_args, kv_vector_t *output_args);

static int uspd_operate_handler(char *op_cmd, kv_vector_t *input_args,
				kv_vector_t *output_args, bool async);

int uspd_call(char *method, struct blob_buf *data,
	      UBUS_USP_CB callback, void *cb_arg);

static void uspd_operate_cb(struct ubus_request *req,
			    int type, struct blob_attr *msg);

static void del_data_cb(struct ubus_request *req,
			int type, struct blob_attr *msg);

static void add_data_cb(struct ubus_request *req,
			int type, struct blob_attr *msg);

static void uspd_set_cb(struct ubus_request *req,
			int type, struct blob_attr *msg);

static void resolve_path_cb(struct ubus_request *req,
			    int type, struct blob_attr *msg);

static int get_schema_path(char *path, char *schema)
{
	char *temp;
	char *tok, *save;

	temp = USP_STRDUP(path);
	tok = strtok_r(temp, ".", &save);
	while (tok != NULL) {
		int num = atoi(tok);
		if (num) {
			strcat(schema, "{i}");
		} else {
			strcat(schema, tok);
		}
		tok = strtok_r(NULL, ".", &save);

		if (tok)
			strcat(schema, ".");
	}
	USP_SAFE_FREE(temp);
	return 0;
}

static void *OperationAsyncThreadMain(void *param)
{
    input_cond_t *cond = (input_cond_t *) param;
    char err_log[128];
    char *err_msg;
    int err = USP_ERR_OK;
    kv_vector_t *output_args;

    memset(err_log, 0, sizeof(err_log));

    output_args = USP_ARG_Create();

    // Exit if unable to signal that this operation is active
    err = USP_SIGNAL_OperationStatus(cond->request_instance, "Active");
    if (err == USP_ERR_OK)
    {
        err = uspd_operate_handler(cond->path, cond->input_args, output_args, true);
    }

    USP_LOG_Info("## Dump async out arg:");
    KV_VECTOR_Dump(output_args);

    err_msg = (err != USP_ERR_OK) ? err_log : NULL;
    USP_SIGNAL_OperationComplete(cond->request_instance, err, err_msg, output_args);

    // Free the input conditions
    USP_FREE(cond);
    return NULL;
}

static int uspd_operate_async(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int err = USP_ERR_OK;
    input_cond_t *cond;

    // Allocate input conditions to pass to thread
    cond = USP_MALLOC(sizeof(input_cond_t));
    memset(cond, 0, sizeof(input_cond_t));

    cond->request_instance = instance;
    strcpy(cond->path, req->path);

    cond->input_args = (kv_vector_t *) USP_MALLOC(sizeof(kv_vector_t));
    KV_VECTOR_Init(cond->input_args);

    for(int i=0; i<input_args->num_entries; ++i) {
	    kv_pair_t *kv = &input_args->vector[i];
	    KV_VECTOR_Add(cond->input_args, kv->key, kv->value);
    }

    // Log the input conditions for the operation
    USP_LOG_Info("=== Conditions ===");
    USP_LOG_Info("instance_number: %d", cond->request_instance);
    KV_VECTOR_Dump(input_args);
    USP_LOG_Info("req path: %s", cond->path);

    err = OS_UTILS_CreateThread(OperationAsyncThreadMain, cond);
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_COMMAND_FAILURE;
    }

    return err;
}

void vendor_async_db_init()
{
	STR_VECTOR_Init(&gs_async_paths);
	STR_VECTOR_Add(&gs_async_paths, "Device.PacketCaptureDiagnostics()");
	STR_VECTOR_Add(&gs_async_paths, "Device.WiFi.NeighboringWiFiDiagnostic()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DeviceInfo.VendorConfigFile.{i}.Backup()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DeviceInfo.VendorConfigFile.{i}.Restore()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DeviceInfo.VendorLogFile.{i}.Upload()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DeviceInfo.FirmwareImage.{i}.Download()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DeviceInfo.FirmwareImage.{i}.Activate()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DSL.Diagnostics.ADSLLineTest()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DSL.Diagnostics.SELTUER()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DSL.Diagnostics.SELTQLN()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DSL.Diagnostics.SELTP()");
	STR_VECTOR_Add(&gs_async_paths, "Device.ATM.Diagnostics.F5Loopback()");
	STR_VECTOR_Add(&gs_async_paths, "Device.Ethernet.WoL.SendMagicPacket()");
	STR_VECTOR_Add(&gs_async_paths, "Device.HPNA.Diagnostics.PHYThroughput()");
	STR_VECTOR_Add(&gs_async_paths, "Device.HPNA.Diagnostics.PerformanceMonitoring()");
	STR_VECTOR_Add(&gs_async_paths, "Device.Ghn.Diagnostics.PHYThroughput()");
	STR_VECTOR_Add(&gs_async_paths, "Device.Ghn.Diagnostics.PerformanceMonitoring()");
	STR_VECTOR_Add(&gs_async_paths, "Device.UPA.Diagnostics.InterfaceMeasurement()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IP.Diagnostics.IPPing()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IP.Diagnostics.TraceRoute()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IP.Diagnostics.DownloadDiagnostics()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IP.Diagnostics.UploadDiagnostics()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IP.Diagnostics.UDPEchoDiagnostics()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IP.Diagnostics.ServerSelectionDiagnostics()");
	STR_VECTOR_Add(&gs_async_paths, "Device.DNS.Diagnostics.NSLookupDiagnostics()");
	STR_VECTOR_Add(&gs_async_paths, "Device.SoftwareModules.InstallDu()");
	STR_VECTOR_Add(&gs_async_paths, "Device.SoftwareModules.DeploymentUnit.{i}.Update()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IoTCapability.{i}.BinaryControl.Toggle()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IoTCapability.{i}.LevelControl.StepUp()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IoTCapability.{i}.LevelControl.StepDown()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IoTCapability.{i}.EnumControl.StepUp()");
	STR_VECTOR_Add(&gs_async_paths, "Device.IoTCapability.{i}.EnumControl.StepDown()");
	STR_VECTOR_Add(&gs_async_paths, "Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.Reset()");
	STR_VECTOR_Add(&gs_async_paths, "Device.LocalAgent.Controller.{i}.E2ESession.Reset()");
	STR_VECTOR_Add(&gs_async_paths, "Device.SoftwareModules.DeploymentUnit.{i}.Uninstall()");
}

void vendor_async_db_clean()
{
	STR_VECTOR_Destroy(&gs_async_paths);
}

bool check_async_command(char *path)
{
	if (INVALID == STR_VECTOR_Find(&gs_async_paths, path))
		return false;
	return true;
}

void vendor_get_arg_init(struct vendor_get_param *vget)
{
	if (vget == NULL)
		return;

	vget->fault = USP_ERR_OK;
	USP_ARG_Init(&vget->kv_vec);
}

static void uspd_operate_cb(struct ubus_request *req, __unused int type, struct blob_attr *msg)
{
	char *str;
	JsonNode *json, *parameters, *member;
	kv_vector_t *kv_out;

	if (!msg)
		return;

	kv_out = (kv_vector_t *) req->priv;
	if (!kv_out)
		return;

	str = blobmsg_format_json_indent(msg, true, -1);
	if (str == NULL)
		return;

	json = json_decode(str);
	if(json == NULL) {
		USP_LOG_Error("Decoding of json failed");
		USP_SAFE_FREE(str);
		return;
	}

	parameters = json_find_member(json, "parameters");
	if (parameters == NULL) {
		json_delete(json);
		USP_SAFE_FREE(str);
		return;
	}

	json_foreach(member, parameters) {
		JsonNode *fault, *parameter, *value;
		fault = json_find_member(member, "fault");
		if (fault != NULL) {
			USP_LOG_Error("Fault in operate");
			json_delete(fault);
			break;
		}

		parameter = json_find_member(member, "parameter");
		value = json_find_member(member, "value");
		if (parameter == NULL || value == NULL) {
			if (parameter)
				json_delete(parameter);
			if (value)
				json_delete(value);
			break;
		}

		if (parameter->tag == JSON_STRING &&
		    value->tag == JSON_STRING) {
			USP_ARG_Add(kv_out, parameter->string_, value->string_);
		}
		json_delete(value);
		json_delete(parameter);
	}

	json_delete(parameters);
	json_delete(json);
	USP_SAFE_FREE(str);
}

static void del_data_cb(struct ubus_request *req, __unused int type, struct blob_attr *msg)
{
	int *fault;
	char *str;
	JsonNode *json, *parameters, *member, *parameter;

	if (!msg)
		return;

	fault = (int *) req->priv;

	if (fault == NULL)
		return;

	str = blobmsg_format_json_indent(msg, true, -1);
	if (str == NULL)
		return;

	json = json_decode(str);
	if(json == NULL) {
		USP_LOG_Error("Decoding of json failed");
		USP_SAFE_FREE(str);
		return;
	}

	parameters = json_find_member(json, "parameters");
	if (parameters == NULL) {
		json_delete(json);
		USP_SAFE_FREE(str);
		return;
	}

	json_foreach(member, parameters){
		parameter = json_find_member(member, "fault");
		if (parameter == NULL)
			break;

		if (parameter->tag == JSON_NUMBER) {
			*fault = parameter->number_;
			json_delete(parameter);
			break;
		}
		json_delete(parameter);
	}
	json_delete(member);
	json_delete(parameters);
	json_delete(json);

	USP_SAFE_FREE(str);
}

static void add_data_cb(struct ubus_request *req, __unused int type, struct blob_attr *msg)
{
	char *str;
	struct vendor_add_arg *vadd;
	JsonNode *json, *parameter, *fault;

	if (!msg)
		return;

	vadd = (struct vendor_add_arg *) req->priv;

	if (vadd == NULL)
		return;

	str = blobmsg_format_json_indent(msg, true, -1);
	if (str == NULL)
		return;

	json = json_decode(str);
	if(json == NULL) {
		USP_LOG_Error("Decoding of json failed");
		USP_SAFE_FREE(str);
		return;
	}

	fault = json_find_member(json, "fault");
	if (fault != NULL) {
		if (fault->tag == JSON_NUMBER) {
			vadd->fault = fault->number_;
		}
		json_delete(fault);
	}

	parameter = json_find_member(json, "instance");
	if (parameter != NULL) {
		if (parameter->tag == JSON_NUMBER) {
			vadd->instance = parameter->number_;
		}
		if (parameter->tag == JSON_STRING) {
			vadd->instance = atoi(parameter->string_);
		}
		json_delete(parameter);
	}

	json_delete(json);
	USP_SAFE_FREE(str);
}

static void uspd_set_cb(struct ubus_request *req, __unused int type, struct blob_attr *msg)
{
	char *str;
	int *ret;
	JsonNode *json, *parameters, *member;

	if (!msg)
		return;

	ret = (int *) req->priv;
	str = blobmsg_format_json_indent(msg, true, -1);

	json = json_decode(str);
	if(json == NULL) {
		USP_LOG_Error("Decoding of json failed");
		USP_SAFE_FREE(str);
		return;
	}

	parameters = json_find_member(json, "parameters");
	if (parameters == NULL) {
		USP_SAFE_FREE(str);
		json_delete(json);
		return;
	}

	json_foreach(member, parameters){
		JsonNode *fault;
		fault = json_find_member(member, "fault");

		if (fault != NULL) {
			if (fault->tag == JSON_NUMBER) {
				USP_LOG_Error("fault occoured |%d|", (int)fault->number_);
				*ret = (int)fault->number_;
			}
			json_delete(fault);
		}
	}
	json_delete(member);
	json_delete(parameters);
	json_delete(json);
	USP_SAFE_FREE(str);
}

int uspd_set_path_value(char *path, char *value, int *fault)
{
	int ret = USP_ERR_OK;
	struct blob_buf b = { };

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "value", value);
	blobmsg_add_string(&b, "proto", USP_PROTO);

	ret = uspd_call("set", &b, uspd_set_cb, fault);

	if (fault && ret != USP_ERR_OK) {
		*fault = ret;
	}

	blob_buf_free(&b);
	return USP_ERR_OK;
}

static void resolve_path_cb(struct ubus_request *req, __unused int type, struct blob_attr *msg)
{
	char *str;
	str_vector_t *vec;
	JsonNode *json, *parameters, *member;

	if (!msg)
		return;

	vec = (str_vector_t *) req->priv;
	str = blobmsg_format_json_indent(msg, true, -1);

	json = json_decode(str);
	if(json == NULL) {
		USP_LOG_Error("Decoding of json failed");
		USP_SAFE_FREE(str);
		return;
	}

	parameters = json_find_member(json, "parameters");
	if (parameters == NULL) {
		USP_SAFE_FREE(str);
		json_delete(json);
		return;
	}

	json_foreach(member, parameters){
		JsonNode *parameter, *fault;
		parameter = json_find_member(member, "parameter");
		fault = json_find_member(member, "fault");

		if (parameter != NULL) {
			if (parameter->tag == JSON_STRING) {
				STR_VECTOR_Add(vec, parameter->string_);
			}
			json_delete(parameter);
		}
		if (fault != NULL) {
			if (fault->tag == JSON_NUMBER)
				USP_LOG_Error("Fault occoured |%d|", (int)fault->number_);
			break;
			json_delete(fault);
		}
	}

	json_delete(member);
	json_delete(parameters);
	json_delete(json);

	USP_SAFE_FREE(str);
}

int uspd_resolve_path(char *path, str_vector_t *sv)
{
	int fault = USP_ERR_OK;
	struct blob_buf b = { };
	char temp[MAX_DM_PATH] = { };
	size_t plen;

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	strncpy(temp, path, MAX_DM_PATH);
	plen = strlen(path) - 1;
	if (path[plen] != '.')
		strcat(temp, ".");

	blobmsg_add_string(&b, "path", temp);
	blobmsg_add_string(&b, "proto", USP_PROTO);

	fault = uspd_call("resolve", &b, resolve_path_cb, sv);

	blob_buf_free(&b);

	return fault;
}

int uspd_resolve_operate_path(char *path, str_vector_t *sv)
{
	int i, fault = USP_ERR_OK;
	struct blob_buf b = { };
	char temp[MAX_DM_PATH] = { };
	char action[MAX_DM_PATH] = { };
	size_t plen;
	str_vector_t op_param;

	STR_VECTOR_Init(&op_param);

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	plen = strlen(path) - 1;
	if (path[plen] == ')') {
		char *last_delim = strrchr(path, '.');
		strcpy(action, last_delim+1);
		strncpy(temp, path, abs(last_delim - path) + 1);
	}
	plen = strlen(temp) - 1;
	if (temp[plen] != '.')
		strcat(temp, ".");

	blobmsg_add_string(&b, "path", temp);
	blobmsg_add_string(&b, "proto", USP_PROTO);

	fault = uspd_call("resolve", &b, resolve_path_cb, &op_param);

	for(i = 0; i < op_param.num_entries; i++) {
		if (sv) {
			snprintf(temp, MAX_DM_PATH, "%s.%s", op_param.vector[i], action);
			STR_VECTOR_Add_IfNotExist(sv, temp);
		} else {
			break;
		}
	}
	blob_buf_free(&b);

	return fault;
}

int uspd_add_object(char *path, struct vendor_add_arg *vadd)
{
	int fault = USP_ERR_OK;
	struct blob_buf b = { };

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "proto", USP_PROTO);

	fault =  uspd_call("add_object", &b, add_data_cb, vadd);

	if (fault != USP_ERR_OK && vadd)
		vadd->fault = fault;

	blob_buf_free(&b);
	return USP_ERR_OK;
}

int uspd_del_object(char *path)
{
	int fault = USP_ERR_OK;
	struct blob_buf b = { };

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "proto", USP_PROTO);

	fault = uspd_call("del_object", &b, del_data_cb, &fault);

	blob_buf_free(&b);
	return USP_ERR_OK;
}

int uspd_operate_exec(char *path, char *command_key, kv_vector_t *input, kv_vector_t *output, int *instance)
{
	char schema_path[MAX_DM_PATH] = {0};
	int fault = USP_ERR_OK;
	bool async_cmd = false;
	dm_req_t req;
	req.path = path;

	get_schema_path(path, schema_path);
	async_cmd = check_async_command(schema_path);

	if (async_cmd) {
            int err = DEVICE_REQUEST_Add(path, command_key, instance);
	    if (err == USP_ERR_OK) {
		    USP_ERR_ClearMessage();
		    fault = uspd_operate_async(&req, input, *instance);
	    } else {
		    USP_LOG_Error("Async cmd(%s) get instance failed", path);
	    }

	} else {
		fault = uspd_operate_sync(&req, NULL, input, output);
	}
	return fault;
}

static int uspd_operate_handler(char *op_cmd, kv_vector_t *input_args, kv_vector_t *output_args, bool async)
{
	int fault = USP_ERR_OK;
	struct blob_buf b = { };
	kv_pair_t *kv;
	char path[MAX_DM_PATH] = {'\0'}, action[MAX_DM_PATH] = {'\0'};
	char *last_delim = strrchr(op_cmd, '.');

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	if (!async) {
		if (output_args)
			KV_VECTOR_Init(output_args);
	}

	// separate path and command
	strcpy(action, last_delim+1);
	strncpy(path, op_cmd, abs(last_delim - op_cmd)+1);

	if(input_args != NULL) {
		void *table = blobmsg_open_table(&b, "input");
		for(int i=0; i<input_args->num_entries; ++i) {
			kv = &input_args->vector[i];
			USP_LOG_Info("[%s:%d] INPUT key |%s| value|%s|",__func__, __LINE__, kv->key, kv->value);
			blobmsg_add_string(&b, kv->key, kv->value);
		}
		blobmsg_close_table(&b, table);
	}


	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "action", action);
	blobmsg_add_string(&b, "proto", USP_PROTO);

	fault = uspd_call("operate", &b, uspd_operate_cb, output_args);

	blob_buf_free(&b);
	return fault;
}

static int uspd_operate_sync(dm_req_t *req, __unused char *command_key, kv_vector_t *input_args, kv_vector_t *output_args)
{
	return uspd_operate_handler(req->path, input_args, output_args, false);
}

int factory_reset()
{
	int res = 0;
	dm_req_t req;
	kv_vector_t input_args, output_args;
	KV_VECTOR_Init(&input_args);
	memset(&req, 0, sizeof(req));

	req.path = "Device.FactoryReset()";
	res = uspd_operate_sync(&req, NULL, &input_args, &output_args);
	KV_VECTOR_Destroy(&input_args);
	KV_VECTOR_Destroy(&output_args);
	return res;
}

int reboot()
{
	int ret = 0;
	dm_req_t req;
	kv_vector_t input_args, output_args;
	KV_VECTOR_Init(&input_args);

	memset(&req, 0, sizeof(req));
	req.path = "Device.Reboot()";
	ret = uspd_operate_sync(&req, NULL, &input_args, &output_args);
	KV_VECTOR_Destroy(&input_args);
	KV_VECTOR_Destroy(&output_args);
	return ret;
}

int vendor_factory_reset_init()
{
	vendor_hook_cb_t callbacks;
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.factory_reset_cb = factory_reset;
	return USP_REGISTER_CoreVendorHooks(&callbacks);
}

int vendor_reset_init()
{
	vendor_hook_cb_t callbacks;
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.reboot_cb = reboot;
	return USP_REGISTER_CoreVendorHooks(&callbacks);
}

static void receive_instance_cb(struct ubus_request *req, __unused int type, struct blob_attr *msg)
{
	JsonNode *json, *parameters, *member;
	str_vector_t *vec;
	char *str;

	if (!msg) {
		USP_LOG_Error("[%s:%d] recieved msg is null",__func__, __LINE__);
		return;
	}

	vec = (str_vector_t *) req->priv;

	if (vec == NULL)
		return;

	str = (char *) blobmsg_format_json_indent(msg, true, -1);
	if (str == NULL)
		return;

	json = json_decode(str);
	if(json == NULL) {
		USP_LOG_Error("Decoding of json failed");
		USP_SAFE_FREE(str);
		return;
	}

	parameters = json_find_member(json, "parameters");
	if (parameters == NULL) {
		json_delete(json);
		USP_SAFE_FREE(str);
		return;
	}

	json_foreach(member, parameters){
		JsonNode *parameter;
		parameter = json_find_member(member, "parameter");

		if (parameter == NULL)
			break;

		if (parameter->tag == JSON_STRING) {
			STR_VECTOR_Add(vec, parameter->string_);
		}
		json_delete(parameter);
	}
	json_delete(member);
	json_delete(parameters);
	json_delete(json);

	USP_SAFE_FREE(str);
}

int uspd_get_instances(char *path, str_vector_t *str_vec)
{
	int fault = USP_ERR_OK;
	struct blob_buf b = { };

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "proto", "usp");

	fault = uspd_call("instances", &b, receive_instance_cb, str_vec);

	blob_buf_free(&b);

	return fault;
}

static void receive_get_cb(struct ubus_request *req, __unused int type, struct blob_attr *msg)
{
	JsonNode *json, *parameters, *member;
	struct vendor_get_param *vget;
	kv_vector_t *kv;
	char *str;

	if (!msg) {
		USP_LOG_Error("[%s:%d] recieved msg is null",__func__, __LINE__);
		return;
	}

	vget = (struct vendor_get_param *) req->priv;

	if (vget == NULL)
		return;

	kv = (kv_vector_t *)&vget->kv_vec;

	str = (char *) blobmsg_format_json_indent(msg, true, -1);
	if (str == NULL) {
		vget->fault = USP_ERR_GENERAL_FAILURE;
		return;
	}

	json = json_decode(str);
	if (json == NULL) {
		vget->fault = USP_ERR_GENERAL_FAILURE;
		USP_SAFE_FREE(str);
		return;
	}

	parameters = json_find_member(json, "parameters");
	if (parameters == NULL) {
		vget->fault = USP_ERR_GENERAL_FAILURE;
		json_delete(json);
		USP_SAFE_FREE(str);
		return;
	}

	json_foreach(member, parameters){
		JsonNode *parameter, *value;

		parameter = json_find_member(member, "parameter");
		value = json_find_member(member, "value");
		if (parameter == NULL || value == NULL) {
			if (parameter)
				json_delete(parameter);
			if (value)
				json_delete(value);
			break;
		}

		if (parameter->tag == JSON_STRING &&
		    value->tag == JSON_STRING) {
			USP_ARG_Add(kv, parameter->string_, value->string_);
		}
		json_delete(parameter);
		json_delete(value);
	}
	json_delete(member);
	json_delete(parameters);
	json_delete(json);
	USP_SAFE_FREE(str);
}

int uspd_get_path_value(char *path, struct vendor_get_param *vget)
{
	int fault = USP_ERR_OK;
	struct blob_buf b = { };

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "proto", "usp");

	// Invoke Ubus to get data from uspd
	fault = uspd_call("get", &b, receive_get_cb, vget);

	if (fault != USP_ERR_OK && vget != NULL)
		vget->fault = fault;

	blob_buf_free(&b);
	return fault;
}

int uspd_get_uniq_kv(char *obj_path, kv_vector_t *params)
{
	int i;
	char temp[MAX_DM_PATH] = { 0 };
	struct vendor_get_param vget;

	vendor_get_arg_init(&vget);
	kv_vector_t *kv_vec = &vget.kv_vec;

	USP_SNPRINTF(temp, MAX_DM_PATH, "%s.Alias", obj_path);

	uspd_get_path_value(temp, &vget);

	for (i = 0; i < kv_vec->num_entries; ++i) {
		KV_VECTOR_Add(params, kv_vec->vector[i].key, kv_vec->vector[i].value);
	}
	KV_VECTOR_Destroy(kv_vec);

	return vget.fault;
}

int uspd_call(char *method, struct blob_buf *data, UBUS_USP_CB callback, void *cb_arg)
{
	uint32_t id;
	struct ubus_context *ctx = ubus_connect(NULL);

	if (!ctx) {
		USP_LOG_Error("[%s:%d] ubus_connect failed",__func__, __LINE__);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (ubus_lookup_id(ctx, "usp.raw", &id)) {
		USP_LOG_Error("[%s:%d] %s not present",__func__, __LINE__, "usp.raw");
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}

	// Invoke Ubus to get data from uspd
	if (ubus_invoke(ctx, id, method, data->head, callback, cb_arg, USPD_TIMEOUT)) {
		USP_LOG_Error("[%s:%d] ubus call failed",__func__, __LINE__);
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}

	ubus_free(ctx);
	return USP_ERR_OK;
}

