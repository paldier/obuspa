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

/**
 * \file vendor_iopsys.c
 *
 * IOPSYS implementation of data model nodes
 * Nodes registered are as per "tr-181-2-12-0-usp" data model definition
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <libubus.h>
#include <libubox/blobmsg_json.h>

#include "usp_err_codes.h"
#include "vendor_defs.h"
#include "vendor_api.h"
#include "data_model.h"
#include "dm_access.h"
#include "usp_api.h"
#include "common_defs.h"
#include "json.h"
#include "vendor_iopsys.h"
#include "path_resolver.h"
#include "str_vector.h"

// Timeout in milliseconds
#define USPD_TIMEOUT 5000
extern bool is_running_cli_local_command;

// Local USPD Database containing the JSON Data
static JsonNode *g_uspd_json_db = NULL;

static bool uspd_set(char *path, char *value);
static int iopsys_dm_instance_init(void);
static int add_object_aliase(char *path);
static bool json_get_param_value(char *path, char *buff);
void (*call_result_func)(struct ubus_request *req, int type, struct blob_attr *msg);

static void store_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
	if (!msg) {
		USP_LOG_Error("[%s:%d] recieved msg is null",__func__, __LINE__);
		return;
	}
	char *str = NULL;
	str = (char *) blobmsg_format_json_indent(msg, true, -1);

	if (str != NULL) {
		if (g_uspd_json_db != NULL)
			json_delete(g_uspd_json_db);

		g_uspd_json_db = json_decode(str);
	}
	USP_SAFE_FREE(str);
}

static void receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
	if (!msg) {
		USP_LOG_Error("[%s:%d] recieved msg is null",__func__, __LINE__);
		return;
	}
	char *str = NULL;
	str = (char *) blobmsg_format_json_indent(msg, true, -1);
	strcpy(req->priv, str);

	USP_SAFE_FREE(str);
}

static void receive_call_result_status(struct ubus_request *req, int type, struct blob_attr *msg)
{
	bool *status = (bool *)req->priv;
	if (!msg) {
		USP_LOG_Error("[%s:%d] recieved msg is null",__func__, __LINE__);
		return;
	}
	char *json_str = NULL;
	json_str = (char *) blobmsg_format_json_indent(msg, true, -1);
	JsonNode *json, *parameters;
	if((json = json_decode(json_str)) == NULL) {
		USP_LOG_Error("[%s:%d] decoding of json failed",__func__, __LINE__);
		free(json_str);
		return;
	}
	if((parameters = json_find_member(json, "parameters")) != NULL) {
		JsonNode *node;
		json_foreach(node, parameters) {
			JsonNode *valueNode;
			valueNode = json_find_member(node, "status");
			if(valueNode->tag == JSON_BOOL) {
				USP_LOG_Debug("status |%d|", valueNode->bool_);
				*status = (bool) valueNode->bool_;
			}
			json_delete(valueNode);
		}
	}
	json_delete(json);
	USP_SAFE_FREE(json_str);
}

static void receive_data_print(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char *str;
	if (!msg)
		return;

	str = blobmsg_format_json_indent(msg, true, -1);
	USP_LOG_Info("%s", str);
	USP_SAFE_FREE(str);
}

/*
 * This function takes care to initialize global json database
 * (g_uspd_json_db) in case json_buff is NULL
 */
int uspd_get(char *path, char *json_buff)
{
	uint32_t id;
	struct ubus_context *ctx = ubus_connect(NULL);
	struct blob_buf b = { };

	if (!ctx) {
		USP_LOG_Error("[%s:%d] ubus_connect failed",__func__, __LINE__);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (ubus_lookup_id(ctx, USP_UBUS, &id)) {
		USP_LOG_Error("[%s:%d] %s not present",__func__, __LINE__, USP_UBUS);
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "path", path);
	json_buff ? (call_result_func = receive_call_result_data) :
		(call_result_func = store_call_result_data);

	if (ubus_invoke(ctx, id, "get", b.head, call_result_func, json_buff, USPD_TIMEOUT)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, path);
		ubus_free(ctx);
		blob_buf_free(&b);
		return USP_ERR_INTERNAL_ERROR;
	}
	blob_buf_free(&b);
	ubus_free(ctx);
	return USP_ERR_OK;
}

int init_uspd_database(char *path)
{
	int status = uspd_get(path, NULL);
	if (status == USP_ERR_OK) {
		USP_LOG_Debug("USPD Database Init done");
	} else {
		USP_LOG_Error("UBUS failue: |Unable to initialize local USPD "
			      "database|");
	}

	return status;
}

void destroy_uspd_json() {
	if (g_uspd_json_db)
		json_delete(g_uspd_json_db);
	g_uspd_json_db = NULL;
}

int uspd_add(dm_req_t *req)
{
	uint32_t id;
	struct ubus_context *ctx = ubus_connect(NULL);
	struct blob_buf b = { };

	if (!ctx) {
		USP_LOG_Error("[%s:%d] ubus_connect failed",__func__, __LINE__);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (!req) {
		USP_LOG_Error("[%s:%d] req is null",__func__, __LINE__);
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (ubus_lookup_id(ctx, USP_UBUS, &id)) {
		USP_LOG_Error("[%s:%d] %s not present",__func__, __LINE__, USP_UBUS);
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "path", req->path);
	if (ubus_invoke(ctx, id, "add_object", b.head, receive_data_print, NULL, USPD_TIMEOUT)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, req->path);
		blob_buf_free(&b);
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}
	blob_buf_free(&b);
	ubus_free(ctx);
	return USP_ERR_OK;
}

int uspd_add_notify(dm_req_t *req)
{
	char path[MAX_DM_PATH];
	int err = USP_ERR_OK;

	USP_SNPRINTF(path, sizeof(path), "%s.Alias", req->path);
	err = add_object_aliase(path);

	return err;
}

int uspd_del(dm_req_t *req)
{
	uint32_t id;
	struct ubus_context *ctx = ubus_connect(NULL);
	struct blob_buf b = { };

	if (!ctx) {
		USP_LOG_Error("[%s:%d] ubus_connect failed",__func__, __LINE__);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (!req) {
		USP_LOG_Error("[%s:%d] req is null",__func__, __LINE__);
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (ubus_lookup_id(ctx, USP_UBUS, &id)) {
		USP_LOG_Error("[%s:%d] %s not present",__func__, __LINE__, USP_UBUS);
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "path", req->path);
	if (ubus_invoke(ctx, id, "del_object", b.head, receive_data_print, NULL, USPD_TIMEOUT)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, req->path);
		ubus_free(ctx);
		blob_buf_free(&b);
		return USP_ERR_INTERNAL_ERROR;
	}
	blob_buf_free(&b);
	ubus_free(ctx);
	return USP_ERR_OK;
}

bool json_get_param_value(char *path, char *buff) {
	bool status = false;
	JsonNode *parameters, *member;

	if (g_uspd_json_db == NULL)
		return status;

	if ((parameters = json_find_member(g_uspd_json_db, "parameters")) != NULL) {
		json_foreach(member, parameters) {
			JsonNode *parameter;
			if ((parameter = json_find_member(member, "parameter")) != NULL) {
				if (!strcmp(parameter->string_, path)) {
					JsonNode *value;
					if ((value = json_find_member(member, "value")) != NULL) {
						strcpy(buff, value->string_);
						status = true;
					}
					break;
				}
			}
		}
	} else {
		USP_LOG_Debug("%s: Parameters tag not found in json database", __func__);
	}
	return status;
}

int json_get_value_index(char *json_buff,char *node, char *buff, uint8_t index)
{
	JsonNode *json, *zeroth, *parameters;
	if((json = json_decode(json_buff)) == NULL) {
		USP_LOG_Error("[%s:%d] json decoding failed",__func__, __LINE__);
		return USP_ERR_GENERAL_FAILURE;
	}
	if((parameters = json_find_member(json, "parameters")) != NULL) {
		if((zeroth = json_find_element(parameters, index)) != NULL) {
			if(node != NULL) {
				JsonNode *parameter;
				parameter = json_find_member(zeroth, "parameter");
				if(parameter->tag == JSON_STRING) {
					strcpy(node, parameter->string_);
				}
				json_delete(parameter);
			}
			if(buff != NULL) {
				JsonNode *value;
				value = json_find_member(zeroth, "value");
				if(value->tag == JSON_STRING) {
					strcpy(buff, value->string_);
				}
				json_delete(value);
			}
			json_delete(zeroth);
		}
		json_delete(parameters);
	}
	json_delete(json);
	return USP_ERR_OK;
}

/*********************************************************************//**
**
** uspd_get_value
**
** Gets the value of req->path
** First lookup into the local USPD Database
** else call usp_get method for the requested path
**
** \param   req - pointer to structure identifying the path
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int uspd_get_value(dm_req_t *req, char *buf, int len)
{
	char json_buff[MAX_DM_VALUE_LEN] = {'\0'};

	if(buf==NULL) {
		USP_LOG_Error("[%s:%d] value buffer is null",__func__, __LINE__);
		return USP_ERR_INTERNAL_ERROR;
	}

	/* First lookup into local uspd_database */
	if (false == json_get_param_value(req->path, buf)) {
		USP_LOG_Debug("Not found in local database:|%s|", req->path);
		if (USP_ERR_OK == uspd_get(req->path, json_buff))
			json_get_value_index(json_buff, NULL, buf, 0);
	}

	len = strlen(buf);
	return USP_ERR_OK;
}

int uspd_operate_sync(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args)
{
	uint32_t id;
	struct ubus_context *ctx = ubus_connect(NULL);
	struct blob_buf b = { };
	kv_pair_t *kv;
	char path[MAX_DM_PATH] = {'\0'}, action[MAX_DM_PATH] = {'\0'};
	char *last_delim = strrchr(req->path, '.');

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	KV_VECTOR_Init(output_args);

	strcpy(action, last_delim+1);
	strncpy(path, req->path, abs(last_delim - req->path)+1);
	USP_LOG_Info("path |%s| action|%s|",path, action);

	if(input_args->num_entries) {
		void *table = blobmsg_open_table(&b, "input");
		for(int i=0; i<input_args->num_entries; ++i) {
			kv = &input_args->vector[i];
			USP_LOG_Info("[%s:%d] INPUT key |%s| value|%s|",__func__, __LINE__, kv->key, kv->value);
			blobmsg_add_string(&b, kv->key, kv->value);
		}
		blobmsg_close_table(&b, table);
	}

	if (!ctx) {
		USP_LOG_Error("[%s:%d] ubus_connect failed",__func__, __LINE__);
		blob_buf_free(&b);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (ubus_lookup_id(ctx, USP_UBUS, &id)) {
		USP_LOG_Error("[%s:%d] %s not present",__func__, __LINE__, USP_UBUS);
		ubus_free(ctx);
		blob_buf_free(&b);
		return USP_ERR_INTERNAL_ERROR;
	}

	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "action", action);

	/* invoke a method on a specific object */
	if (ubus_invoke(ctx, id, "operate", b.head, receive_data_print, NULL, USPD_TIMEOUT)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, path);
		ubus_free(ctx);
		blob_buf_free(&b);
		return USP_ERR_INTERNAL_ERROR;
	}
	ubus_free(ctx);
	blob_buf_free(&b);
	return USP_ERR_OK;
}

static int add_object_aliase(char *path)
{
	int err = USP_ERR_OK;
	char json_buff[MAX_DM_VALUE_LEN] = {'\0'};

	if(USP_ERR_OK != uspd_get(path, json_buff))
		return USP_ERR_GENERAL_FAILURE;

	JsonNode *json, *parameters;
	if((json = json_decode(json_buff)) == NULL) {
		USP_LOG_Error("[%s:%d] json decode failed",__func__, __LINE__);
		return USP_ERR_GENERAL_FAILURE;
	}
	if((parameters = json_find_member(json, "parameters")) != NULL) {
		JsonNode *node;
		json_foreach(node, parameters) {
			JsonNode *parameter, *valueNode;
			parameter = json_find_member(node, "parameter");
			valueNode = json_find_member(node, "value");
			if((parameter->tag & valueNode->tag) == JSON_STRING) {
				USP_LOG_Debug("parameter |%s|, value |%s|", parameter->string_, valueNode->string_);
				if(0 == strcmp(valueNode->string_, "")) {
					char *alias=NULL;
					err = DM_ACCESS_GetString(path, &alias);
					uspd_set(path, alias);
					USP_SAFE_FREE(alias);
				} else {
					err = DATA_MODEL_SetParameterInDatabase(parameter->string_, valueNode->string_);
				}
			}
			json_delete(parameter);
			json_delete(valueNode);
		}
	}
	json_delete(json);
	return(err);
}

static bool uspd_set(char *path, char *value)
{
	uint32_t id;
	bool status = false;
	struct ubus_context *ctx = ubus_connect(NULL);
	struct blob_buf b = { };

	if (!ctx) {
		USP_LOG_Error("[%s:%d] ubus connect failed",__func__, __LINE__);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (ubus_lookup_id(ctx, USP_UBUS, &id)) {
		USP_LOG_Error("[%s:%d] %s not available",__func__, __LINE__, USP_UBUS);
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "value", value);
	if (ubus_invoke(ctx, id, "set", b.head, receive_call_result_status, &status, USPD_TIMEOUT)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, path);
		blob_buf_free(&b);
		ubus_free(ctx);
		return false;
	}
	blob_buf_free(&b);
	ubus_free(ctx);
	return status;
}
/*********************************************************************//**
**
** uspd_set_value
**
** Gets the value of req->path
**
** \param   req - pointer to structure identifying the path
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int uspd_set_value(dm_req_t *req, char *buf)
{
	uspd_set(req->path, buf);
	return USP_ERR_OK;
}

int vendor_device_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_ROOT "Device"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ROOT ".RootDataModelVersion", uspd_get_value, DM_STRING);
	return err;
}

int vendor_Services_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_SERVICE_ROOT "Device.Services"
#define DEVICE_SERVICE_VOICESERVICE_ROOT "Device.Services.VoiceService"

	err |= USP_REGISTER_Object(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Alias", NULL);

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.ButtonMap", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.DigitMap", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.FaxPassThrough", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.FaxT38", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.FileBasedRingGeneration", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.FileBasedToneGeneration", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.MaxLineCount", uspd_get_value, DM_UINT); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.MaxProfileCount", uspd_get_value, DM_UINT); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.MaxSessionCount", uspd_get_value, DM_UINT); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.MaxSessionsPerLine", uspd_get_value, DM_UINT); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.ModemPassThrough", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.NumberingPlan", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.PSTNSoftSwitchOver", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.PatternBasedRingGeneration", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.PatternBasedToneGeneration", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.RTCP", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.RTPRedundancy", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.Regions", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.RingDescriptionsEditable", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.RingFileFormats", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.RingGeneration", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.RingPatternEditable", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SIP.EventSubscription", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SIP.Extensions", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SIP.ResponseMap", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SIP.Role", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SIP.TLSAuthenticationProtocols", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SIP.TLSEncryptionProtocols", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SIP.TLSKeyExchangeProtocols", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SIP.Transports", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SIP.URISchemes", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SRTP", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.SignalingProtocols", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.ToneDescriptionsEditable", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.ToneFileFormats", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.ToneGeneration", uspd_get_value, DM_BOOL); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.VoicePortTests", uspd_get_value, DM_BOOL);


	err |= USP_REGISTER_Object(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.Codecs.{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
        err |= USP_REGISTER_DBParam_Alias(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.Codecs.{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.Codecs.{i}.BitRate", uspd_get_value, DM_UINT); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.Codecs.{i}.Codec", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.Codecs.{i}.EntryID", uspd_get_value, DM_UINT); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.Codecs.{i}.PacketizationPeriod", uspd_get_value, DM_STRING); 
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.Capabilities.Codecs.{i}.SilenceSuppression", uspd_get_value, DM_BOOL); 

	err |= USP_REGISTER_Object(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.DTMFMethod", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.FaxT38.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.MaxSessions", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.NumberOfLines", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.RTP.DSCPMark", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.RTP.LocalPortMax", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.RTP.LocalPortMin", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.RTP.RTCP.Enable", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.RTP.RTCP.TxRepeatInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.RTP.SRTP.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Region", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Reset", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.OutboundProxy", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.OutboundProxyPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.ProxyServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.ProxyServerPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.ProxyServerTransport", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.ReInviteExpires", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.RegisterExpires", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.RegisterRetryInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.RegistrarServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.RegistrarServerPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.RegistrarServerTransport", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.RegistrationPeriod", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.UserAgentDomain", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.UserAgentPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.UserAgentTransport", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SIP.X_IOPSYS_EU_CallLines", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.ServiceProviderInfo.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.SignalingProtocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	err |= USP_REGISTER_Object(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.CallState", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.CallingFeatures.CallWaitingEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.CallingFeatures.CallerIDName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.DirectoryNumber", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.SIP.AuthPassword", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.SIP.AuthUserName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.SIP.URI", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.VoiceProcessing.EchoCancellationEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.X_IOPSYS_EU_Confort_Noise_Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.X_IOPSYS_EU_LineProfile", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.X_IOPSYS_EU_TELLine", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	err |= USP_REGISTER_Object(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}.BitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}.Codec", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}.EntryID", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}.PacketizationPeriod", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}.Priority", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_SERVICE_VOICESERVICE_ROOT ".{i}.VoiceProfile.{i}.Line.{i}.Codec.List.{i}.SilenceSuppression", uspd_get_value, DM_BOOL);

	return err;
}

int vendor_DeviceInfo_init(void)
{
	int err = USP_ERR_OK;
#define DEVICEINFO_ROOT "Device.DeviceInfo"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".DeviceCategory", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".Manufacturer", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".ManufacturerOUI", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".CID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".PEN", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICEINFO_ROOT ".FriendlyName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".ModelName", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".ModelNumber", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".Description", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".ProductClass", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".SerialNumber", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".HardwareVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".SoftwareVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".ActiveFirmwareImage", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICEINFO_ROOT ".BootFirmwareImage", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".AdditionalHardwareVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".AdditionalSoftwareVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICEINFO_ROOT ".ProvisioningCode", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".UpTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_ROOT ".FirstUseDate", uspd_get_value, DM_DATETIME);

#define DEVICEINFO_VENDORCONFIG_ROOT "Device.DeviceInfo.VendorConfigFile"

	err |= USP_REGISTER_Object(DEVICEINFO_VENDORCONFIG_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICEINFO_VENDORCONFIG_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICEINFO_ROOT ".VendorConfigFileNumberOfEntries",
			DEVICEINFO_VENDORCONFIG_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_VENDORCONFIG_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_VENDORCONFIG_ROOT ".{i}.Version", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_VENDORCONFIG_ROOT ".{i}.Date", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_VENDORCONFIG_ROOT ".{i}.Description", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_VENDORCONFIG_ROOT ".{i}.UseForBackupRestore", uspd_get_value, DM_BOOL);
	char *unique_keys[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICEINFO_VENDORCONFIG_ROOT ".{i}", unique_keys, NUM_ELEM(unique_keys));

#define DEVICEINFO_MEMORYSTATUS_ROOT "Device.DeviceInfo.MemoryStatus"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_MEMORYSTATUS_ROOT ".Total", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_MEMORYSTATUS_ROOT ".Free", uspd_get_value, DM_UINT);

#define DEVICEINFO_PROCESSSTATUS_ROOT "Device.DeviceInfo.ProcessStatus"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_PROCESSSTATUS_ROOT ".CPUUsage", uspd_get_value, DM_UINT);

#define PROCESSSTATUS_PROCESS_ROOT "Device.DeviceInfo.ProcessStatus.Process"
	err |= USP_REGISTER_Param_NumEntries(DEVICEINFO_PROCESSSTATUS_ROOT ".ProcessNumberOfEntries", PROCESSSTATUS_PROCESS_ROOT ".{i}");
	//err |= USP_REGISTER_Object(PROCESSSTATUS_PROCESS_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(PROCESSSTATUS_PROCESS_ROOT ".{i}.PID", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PROCESSSTATUS_PROCESS_ROOT ".{i}.Command", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PROCESSSTATUS_PROCESS_ROOT ".{i}.Size", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PROCESSSTATUS_PROCESS_ROOT ".{i}.Priority", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PROCESSSTATUS_PROCESS_ROOT ".{i}.CPUTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PROCESSSTATUS_PROCESS_ROOT ".{i}.State", uspd_get_value, DM_STRING);
	char *unique_keys_process[] = { "PID" };
	err |= USP_REGISTER_Object_UniqueKey(PROCESSSTATUS_PROCESS_ROOT ".{i}", unique_keys_process, NUM_ELEM(unique_keys_process));

#define DEVICEINFO_TEMPSTATUS_ROOT "Device.DeviceInfo.TemperatureStatus"
#define TEMPSTATUS_TEMPSENSOR_ROOT "Device.DeviceInfo.TemperatureStatus.TemperatureSensor"
	err |= USP_REGISTER_Object(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICEINFO_TEMPSTATUS_ROOT ".TemperatureSensorNumberOfEntries", TEMPSTATUS_TEMPSENSOR_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.ResetTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.Value", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.LastUpdate", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.MinValue", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.MinTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.MaxValue", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.MaxTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.LowAlarmValue", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.LowAlarmTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.HighAlarmValue", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.PollingInterval", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}.HighAlarmTime", uspd_get_value, DM_DATETIME);
	char *unique_keys_temp[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(TEMPSTATUS_TEMPSENSOR_ROOT ".{i}", unique_keys_temp, NUM_ELEM(unique_keys_temp));

#define DEVICEINFO_NETWORKPROP_ROOT "Device.DeviceInfo.NetworkProperties"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_NETWORKPROP_ROOT ".MaxTCPWindowSize", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_NETWORKPROP_ROOT ".TCPImplementation", uspd_get_value, DM_STRING);

#define DEVICEINFO_PROCESSOR_ROOT "Device.DeviceInfo.Processor"
	err |= USP_REGISTER_Object(DEVICEINFO_PROCESSOR_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICEINFO_PROCESSOR_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICEINFO_ROOT ".ProcessorNumberOfEntries", DEVICEINFO_PROCESSOR_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_PROCESSOR_ROOT ".{i}.Architecture", uspd_get_value, DM_STRING);
	char *unique_keys_processor[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICEINFO_PROCESSOR_ROOT ".{i}", unique_keys_processor, NUM_ELEM(unique_keys_processor));

#define DEVICEINFO_VENDORLOGFILE_ROOT "Device.DeviceInfo.VendorLogFile"
	err |= USP_REGISTER_Object(DEVICEINFO_VENDORLOGFILE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICEINFO_VENDORLOGFILE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICEINFO_ROOT ".VendorLogFileNumberOfEntries", DEVICEINFO_VENDORLOGFILE_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_VENDORLOGFILE_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_VENDORLOGFILE_ROOT ".{i}.MaximumSize", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_VENDORLOGFILE_ROOT ".{i}.Persistent", uspd_get_value, DM_BOOL);
	char *unique_keys_log[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICEINFO_VENDORLOGFILE_ROOT ".{i}", unique_keys_log, NUM_ELEM(unique_keys_log));

#define DEVICEINFO_LOCATION_ROOT "Device.DeviceInfo.Location"
	err |= USP_REGISTER_Object(DEVICEINFO_LOCATION_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(DEVICEINFO_LOCATION_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICEINFO_ROOT ".LocationNumberOfEntries", DEVICEINFO_PROCESSOR_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_LOCATION_ROOT ".{i}.Source", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_LOCATION_ROOT ".{i}.AcquiredTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_LOCATION_ROOT ".{i}.ExternalSource", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_LOCATION_ROOT ".{i}.ExternalProtocol", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICEINFO_LOCATION_ROOT ".{i}.DataObject", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_location[] = { "Source", "ExternalSource" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICEINFO_LOCATION_ROOT ".{i}", unique_keys_location, NUM_ELEM(unique_keys_location));

#define DEVICEINFO_FIRMWAREIMAGE_ROOT "Device.DeviceInfo.FirmwareImage"
	err |= USP_REGISTER_Object(DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICEINFO_ROOT ".FirmwareImageNumberOfEntries", DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}.Version", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}.Available", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}.BootFailureLog", uspd_get_value, DM_STRING);
	char *unique_keys_fwimage[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}", unique_keys_fwimage, NUM_ELEM(unique_keys_fwimage));


	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_Time_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_TIME_ROOT "Device.Time"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_TIME_ROOT ".Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer1", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer2", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer3", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer4", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer5", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	// CurrentLocalTime and LocalTimeZone defined in core
	// err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_TIME_ROOT ".CurrentLocalTime", uspd_get_value, DM_DATETIME); Already registered
	// err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".LocalTimeZone", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_UserInterface_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_USERINTERFACE_ROOT "Device.UserInterface"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".PasswordRequired", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".PasswordUserSelectable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".UpgradeAvailable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".WarrantyDate", uspd_get_value, uspd_set_value, NULL, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".ISPName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".ISPHelpDesk", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".ISPHomePage", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".ISPMailServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".ISPNewsServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".AutoUpdateServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".UserUpdateServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_USERINTERFACE_ROOT ".AvailableLanguages", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_ROOT ".CurrentLanguage", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define USERINTERFACE_RA_ROOT "Device.UserInterface.RemoteAccess"
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_RA_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_RA_ROOT ".Port", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(USERINTERFACE_RA_ROOT ".SupportedProtocols", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_RA_ROOT ".Protocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define USERINTERFACE_LOCALDISPLAY_ROOT "Device.UserInterface.LocalDisplay"
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_LOCALDISPLAY_ROOT ".Movable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_LOCALDISPLAY_ROOT ".Resizable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_LOCALDISPLAY_ROOT ".PosX", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_LOCALDISPLAY_ROOT ".PosY", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_LOCALDISPLAY_ROOT ".Width", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_LOCALDISPLAY_ROOT ".Height", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(USERINTERFACE_LOCALDISPLAY_ROOT ".DisplayWidth", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(USERINTERFACE_LOCALDISPLAY_ROOT ".DisplayHeight", uspd_get_value, DM_UINT);

#define USERINTERFACE_MESSAGES_ROOT "Device.UserInterface.Messages"
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_MESSAGES_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_MESSAGES_ROOT ".Title", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_MESSAGES_ROOT ".SubTitle", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_MESSAGES_ROOT ".Text", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_MESSAGES_ROOT ".IconType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERINTERFACE_MESSAGES_ROOT ".RequestedNumberOfRepetitions", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(USERINTERFACE_MESSAGES_ROOT ".ExecutedNumberOfRepetitions", uspd_get_value, DM_UINT);

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_InterfaceStack_init(void)
{
#define DEVICE_INTERFACESTACK_ROOT "Device.InterfaceStack"
	int err = USP_ERR_OK;
	err |= USP_REGISTER_Object(DEVICE_INTERFACESTACK_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_INTERFACESTACK_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ROOT ".InterfaceStackNumberOfEntries", DEVICE_INTERFACESTACK_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_INTERFACESTACK_ROOT ".{i}.HigherLayer", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_INTERFACESTACK_ROOT ".{i}.LowerLayer", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_INTERFACESTACK_ROOT ".{i}.HigherAlias", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_INTERFACESTACK_ROOT ".{i}.LowerAlias", uspd_get_value, DM_STRING);
	char *unique_keys_intstack[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICEINFO_FIRMWAREIMAGE_ROOT ".{i}", unique_keys_intstack, NUM_ELEM(unique_keys_intstack));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_DSL_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_DSL_ROOT "Device.DSL"
#define DSL_LINE_ROOT "Device.DSL.Line"
	err |= USP_REGISTER_Object(DSL_LINE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DSL_LINE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DSL_ROOT ".LineNumberOfEntries", DSL_LINE_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DSL_LINE_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DSL_LINE_ROOT ".{i}.EnableDataGathering", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DSL_LINE_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Upstream", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.FirmwareVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.LinkStatus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.StandardsSupported", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTSE", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.StandardUsed", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTSUSed", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.LineEncoding", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.AllowedProfiles", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.CurrentProfile", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.PowerManagementState", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.SuccessFailureCause", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.UPBOKLER", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.UPBOKLEPb", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.UPBOKLERPb", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.RXTHRSHds", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.ACTRAMODEds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.ACTRAMODEus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.ACTINPROCds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.ACTINPROCus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.SNRMROCds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.SNRMROCus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.LastStateTransmittedDownstream", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.LastStateTransmittedUpstream", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.UPBOKLE", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.MREFPSDds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.MREFPSDus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.LIMITMASK", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.US0MASK", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.TRELLISds", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.TRELLISus", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.ACTSNRMODEds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.ACTSNRMODEus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.VirtualNoisePSDds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.VirtualNoisePSDus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.ACTUALCE", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.LineNumber", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.UpstreamMaxBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.DownstreamMaxBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.UpstreamNoiseMargin", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.DownstreamNoiseMargin", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.SNRMpbus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.SNRMpbds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.INMIATOds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.INMIATSds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.INMCCds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.INMINPEQMODEds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.UpstreamAttenuation", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.DownstreamAttenuation", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.UpstreamPower", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.DownstreamPower", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTURVendor", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTURCountry", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTURANSIStd", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTURANSIRev", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTUCVendor", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTUCCountry", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTUCANSIStd", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.XTUCANSIRev", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TotalStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.ShowtimeStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.LastShowtimeStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.CurrentDayStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.QuarterHourStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.Total.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.Total.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.Showtime.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.Showtime.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.LastShowtime.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.LastShowtime.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.CurrentDay.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.CurrentDay.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.QuarterHour.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.QuarterHour.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.HLOGGds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.HLOGGus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.HLOGpsds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.HLOGpsus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.HLOGMTds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.HLOGMTus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.QLNGds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.QLNGus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.QLNpsds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.QLNpsus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.QLNMTds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.QLNMTus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.SNRGds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.SNRGus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.SNRpsds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.SNRpsus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.SNRMTds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.SNRMTus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.LATNds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.LATNus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.SATNds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.TestParams.SATNus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.DataGathering.LoggingDepthR", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.DataGathering.ActLoggingDepthReportingR", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_LINE_ROOT ".{i}.Stats.DataGathering.EventTraceBufferR", uspd_get_value, DM_STRING);
	char *unique_keys_dslline[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DSL_LINE_ROOT ".{i}", unique_keys_dslline, NUM_ELEM(unique_keys_dslline));

#define DSL_CHANNEL_ROOT "Device.DSL.Channel"
	err |= USP_REGISTER_Object(DSL_CHANNEL_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DSL_CHANNEL_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DSL_ROOT ".ChannelNumberOfEntries", DSL_CHANNEL_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DSL_CHANNEL_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.LowerLayers", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.LinkEncapsulationSupported", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.LinkEncapsulationUsed", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.LPATH", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.INTLVDEPTH", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.INTLVBLOCK", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.ActualInterleavingDelay", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.ACTINP", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.INPREPORT", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.NFEC", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.RFEC", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.LSYMB", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.UpstreamCurrRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.DownstreamCurrRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.ACTNDR", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.ACTINPREIN", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.TotalStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.ShowtimeStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.LastShowtimeStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.CurrentDayStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.QuarterHourStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Total.XTURFECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Total.XTUCFECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Total.XTURHECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Total.XTUCHECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Total.XTURCRCErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Total.XTUCCRCErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Showtime.XTURFECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Showtime.XTUCFECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Showtime.XTURHECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Showtime.XTUCHECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Showtime.XTURCRCErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.Showtime.XTUCCRCErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.LastShowtime.XTURFECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.LastShowtime.XTUCFECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.LastShowtime.XTURHECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.LastShowtime.XTUCHECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.LastShowtime.XTURCRCErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.LastShowtime.XTUCCRCErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.QuarterHour.XTURFECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.QuarterHour.XTUCFECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.QuarterHour.XTURHECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.QuarterHour.XTUCHECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.QuarterHour.XTURCRCErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_CHANNEL_ROOT ".{i}.Stats.QuarterHour.XTUCCRCErrors", uspd_get_value, DM_UINT);

	char *unique_keys_dslchannel[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DSL_CHANNEL_ROOT ".{i}", unique_keys_dslchannel, NUM_ELEM(unique_keys_dslchannel));

#define DSL_BG_ROOT "Device.DSL.BondingGroup"
	err |= USP_REGISTER_Object(DSL_BG_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DSL_BG_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DSL_ROOT ".BondingGroupNumberOfEntries", DSL_BG_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DSL_BG_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.LowerLayers", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.GroupStatus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.GroupID", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.BondSchemesSupported", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.BondScheme", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.GroupCapacity", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.RunningTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.TargetUpRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.TargetDownRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.ThreshLowUpRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.ThreshLowDownRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.UpstreamDifferentialDelayTolerance", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.DownstreamDifferentialDelayTolerance", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.TotalStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDayStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHourStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.FailureReasons", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.UpstreamRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.DownstreamRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.UpstreamPacketLoss", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.DownstreamPacketLoss", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.UpstreamDifferentialDelay", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.DownstreamDifferentialDelay", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.FailureCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.ErroredSeconds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.SeverelyErroredSeconds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.Total.UnavailableSeconds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.FailureReasons", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.UpstreamRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.DownstreamRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.UpstreamPacketLoss", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.DownstreamPacketLoss", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.UpstreamDifferentialDelay", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.DownstreamDifferentialDelay", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.FailureCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.ErroredSeconds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.SeverelyErroredSeconds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.CurrentDay.UnavailableSeconds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.FailureReasons", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.UpstreamRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.DownstreamRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.UpstreamPacketLoss", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.DownstreamPacketLoss", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.UpstreamDifferentialDelay", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.DownstreamDifferentialDelay", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.FailureCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.ErroredSeconds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.SeverelyErroredSeconds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Stats.QuarterHour.UnavailableSeconds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PAFErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PAFSmallFragments", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PAFLargeFragments", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PAFBadFragments", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PAFLostFragments", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PAFLateFragments", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PAFLostStarts", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PAFLostEnds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PAFOverflows", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.PauseFramesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.CRCErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.AlignmentErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.ShortPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.LongPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.OverflowErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DSL_BG_ROOT ".{i}.Ethernet.Stats.FramesDropped", uspd_get_value, DM_UINT);

	char *unique_keys_dslbg[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DSL_BG_ROOT ".{i}", unique_keys_dslbg, NUM_ELEM(unique_keys_dslbg));

#define BG_BC_ROOT DSL_BG_ROOT ".{i}.BondedChannel"
	err |= USP_REGISTER_Object(BG_BC_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(BG_BC_ROOT".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DSL_BG_ROOT ".{i}.BondedChannelNumberOfEntries", BG_BC_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(BG_BC_ROOT ".{i}.Channel", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(BG_BC_ROOT ".{i}.Ethernet.Stats.UnderflowErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BG_BC_ROOT ".{i}.Ethernet.Stats.CRCErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BG_BC_ROOT ".{i}.Ethernet.Stats.AlignmentErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BG_BC_ROOT ".{i}.Ethernet.Stats.ShortPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BG_BC_ROOT ".{i}.Ethernet.Stats.LongPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BG_BC_ROOT ".{i}.Ethernet.Stats.OverflowErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BG_BC_ROOT ".{i}.Ethernet.Stats.PauseFramesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BG_BC_ROOT ".{i}.Ethernet.Stats.FramesDropped", uspd_get_value, DM_UINT);

	char *unique_keys_bgbc[] = { "Channel" };
	err |= USP_REGISTER_Object_UniqueKey(BG_BC_ROOT ".{i}", unique_keys_bgbc, NUM_ELEM(unique_keys_bgbc));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_FAST_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_FAST_ROOT "Device.FAST"
#define FAST_LINE_ROOT "Device.FAST.Line"
	err |= USP_REGISTER_Object(FAST_LINE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(FAST_LINE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_FAST_ROOT ".LineNumberOfEntries", FAST_LINE_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(FAST_LINE_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(FAST_LINE_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Upstream", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.FirmwareVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.LinkStatus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.AllowedProfiles", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.CurrentProfile", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.PowerManagementState", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.SuccessFailureCause", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.UPBOKLER", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.LastTransmittedDownstreamSignal", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.LastTransmittedUpstreamSignal", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.UPBOKLE", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.LineNumber", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.UpstreamMaxBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.DownstreamMaxBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.UpstreamNoiseMargin", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.DownstreamNoiseMargin", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.UpstreamAttenuation", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.DownstreamAttenuation", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.UpstreamPower", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.DownstreamPower", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.SNRMRMCds", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.SNRMRMCus", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.BITSRMCpsds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.BITSRMCpsus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.FEXTCANCELds", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.FEXTCANCELus", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.ETRds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.ETRus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.ATTETRds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.ATTETRus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.MINEFTR", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TotalStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.ShowtimeStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtimeStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDayStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHourStart", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.LOSS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.LORS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.UAS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.RTXUC", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.RTXTX", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.SuccessBSW", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.SuccessSRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.SuccessFRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.SuccessRPA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Total.SuccessTIGA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.LOSS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.LORS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.UAS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.RTXUC", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.RTXTX", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.SuccessBSW", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.SuccessSRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.SuccessFRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.SuccessRPA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.Showtime.SuccessTIGA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.LOSS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.LORS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.UAS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.RTXUC", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.RTXTX", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.SuccessBSW", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.SuccessSRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.SuccessFRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.SuccessRPA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.LastShowtime.SuccessTIGA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.LOSS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.LORS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.UAS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.RTXUC", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.RTXTX", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.SuccessBSW", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.SuccessSRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.SuccessFRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.SuccessRPA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.CurrentDay.SuccessTIGA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.ErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.SeverelyErroredSecs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.LOSS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.LORS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.UAS", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.RTXUC", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.RTXTX", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.SuccessBSW", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.SuccessSRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.SuccessFRA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.SuccessRPA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.QuarterHour.SuccessTIGA", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.SNRGds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.SNRGus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.SNRpsds", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.SNRpsus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.SNRMTds", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.SNRMTus", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.ACTINP", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.NFEC", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.RFEC", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.UpstreamCurrRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.DownstreamCurrRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FAST_LINE_ROOT ".{i}.Stats.TestParams.ACTINPREIN", uspd_get_value, DM_UINT);

	char *unique_keys_fastline[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(FAST_LINE_ROOT ".{i}", unique_keys_fastline, NUM_ELEM(unique_keys_fastline));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_Optical_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_OPTICAL_ROOT "Device.Optical"
#define OPTICAL_INT_ROOT "Device.Optical.Interface"
	err |= USP_REGISTER_Object(OPTICAL_INT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(OPTICAL_INT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_OPTICAL_ROOT ".InterfaceNumberOfEntries", OPTICAL_INT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(OPTICAL_INT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(OPTICAL_INT_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Upstream", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.OpticalSignalLevel", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.LowerOpticalThreshold", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.UpperOpticalThreshold", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.TransmitOpticalLevel", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.LowerTransmitPowerThreshold", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.UpperTransmitPowerThreshold", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(OPTICAL_INT_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);

	char *unique_keys_opticalint[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(OPTICAL_INT_ROOT ".{i}", unique_keys_opticalint, NUM_ELEM(unique_keys_opticalint));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_Cellular_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_CELLULAR_ROOT "Device.Cellular"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_CELLULAR_ROOT ".RoamingEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CELLULAR_ROOT ".RoamingStatus", uspd_get_value, DM_STRING);
#define CELLULAR_INT_ROOT "Device.Cellular.Interface"
	err |= USP_REGISTER_Object(CELLULAR_INT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(CELLULAR_INT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_CELLULAR_ROOT ".InterfaceNumberOfEntries", CELLULAR_INT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_INT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_INT_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Upstream", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.IMEI", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.SupportedAccessTechnologies", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_INT_ROOT ".{i}.PreferredAccessTechnology", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.CurrentAccessTechnology", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.AvailableNetworks", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_INT_ROOT ".{i}.NetworkRequested", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.NetworkInUse", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.RSSI", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.UpstreamMaxBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.DownstreamMaxBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.USIM.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.USIM.IMSI", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.USIM.ICCID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.USIM.MSISDN", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_INT_ROOT ".{i}.USIM.PINCheck", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_INT_ROOT ".{i}.USIM.PIN", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(CELLULAR_INT_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);

	char *unique_keys_cellularint[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(CELLULAR_INT_ROOT ".{i}", unique_keys_cellularint, NUM_ELEM(unique_keys_cellularint));

#define CELLULAR_AP_ROOT "Device.Cellular.AccessPoint"
	err |= USP_REGISTER_Object(CELLULAR_AP_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(CELLULAR_AP_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_CELLULAR_ROOT ".AccessPointNumberOfEntries", CELLULAR_AP_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_AP_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_AP_ROOT ".{i}.APN", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_AP_ROOT ".{i}.Username", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_AP_ROOT ".{i}.Password", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_AP_ROOT ".{i}.Proxy", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_AP_ROOT ".{i}.ProxyPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(CELLULAR_AP_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	char *unique_keys_cellularap[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(CELLULAR_AP_ROOT ".{i}", unique_keys_cellularap, NUM_ELEM(unique_keys_cellularap));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_ATM_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_ATM_ROOT "Device.ATM"
#define ATM_LINK_ROOT DEVICE_ATM_ROOT ".Link"
	err |= USP_REGISTER_Object(ATM_LINK_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ATM_LINK_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ATM_ROOT ".LinkNumberOfEntries", ATM_LINK_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.LinkType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.AutoConfig", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.DestinationAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.Encapsulation", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.FCSPreserved", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.VCSearchList", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.AAL", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.TransmittedBlocks", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.ReceivedBlocks", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.CRCErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ATM_LINK_ROOT ".{i}.Stats.HECErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.QoS.QoSClass", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.QoS.PeakCellRate", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.QoS.MaximumBurstSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ATM_LINK_ROOT ".{i}.QoS.SustainableCellRate", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_atm[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(ATM_LINK_ROOT ".{i}", unique_keys_atm, NUM_ELEM(unique_keys_atm));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_PTM_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_PTM_ROOT "Device.PTM"
#define PTM_LINK_ROOT DEVICE_PTM_ROOT ".Link"
	err |= USP_REGISTER_Object(PTM_LINK_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(PTM_LINK_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_PTM_ROOT ".LinkNumberOfEntries", PTM_LINK_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(PTM_LINK_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(PTM_LINK_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.MACAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PTM_LINK_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);
	char *unique_keys_ptm[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(PTM_LINK_ROOT ".{i}", unique_keys_ptm, NUM_ELEM(unique_keys_ptm));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_Ethernet_init(void)
{
	int err = USP_ERR_OK;

#define DEVICE_ETHERNET_ROOT "Device.Ethernet"
#define ETHERNET_INTERFACE_ROOT "Device.Ethernet.Interface"
	err |= USP_REGISTER_Object(ETHERNET_INTERFACE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ETHERNET_INTERFACE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ETHERNET_ROOT ".InterfaceNumberOfEntries", ETHERNET_INTERFACE_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_INTERFACE_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_INTERFACE_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Upstream", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.MACAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_INTERFACE_ROOT ".{i}.MaxBitRate", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.CurrentBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_INTERFACE_ROOT ".{i}.DuplexMode", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.EEECapability", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_INTERFACE_ROOT ".{i}.EEEEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_INTERFACE_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);
	char *unique_keys_ethinterface[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(ETHERNET_INTERFACE_ROOT ".{i}", unique_keys_ethinterface, NUM_ELEM(unique_keys_ethinterface));

#define ETHERNET_LINK_ROOT "Device.Ethernet.Link"
	err |= USP_REGISTER_Object(ETHERNET_LINK_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ETHERNET_LINK_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ETHERNET_ROOT ".LinkNumberOfEntries", ETHERNET_LINK_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_LINK_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_LINK_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.MACAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_LINK_ROOT ".{i}.PriorityTagging", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LINK_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);

	char *unique_keys_link[] = { "Name", "MACAddress" };
	err |= USP_REGISTER_Object_UniqueKey(ETHERNET_LINK_ROOT ".{i}", unique_keys_link, NUM_ELEM(unique_keys_link));

#define ETHERNET_VLANT_ROOT "Device.Ethernet.VLANTermination"
	err |= USP_REGISTER_Object(ETHERNET_VLANT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ETHERNET_VLANT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ETHERNET_ROOT ".VLANTerminationNumberOfEntries", ETHERNET_VLANT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_VLANT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_VLANT_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_VLANT_ROOT ".{i}.VLANID", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_VLANT_ROOT ".{i}.TPID", uspd_get_value, uspd_set_value, NULL, DM_UINT);

	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_VLANT_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);

	char *unique_keys_vlant[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(ETHERNET_VLANT_ROOT ".{i}", unique_keys_vlant, NUM_ELEM(unique_keys_vlant));

#define ETHERNET_RMONSTATS_ROOT "Device.Ethernet.RMONStats"
	err |= USP_REGISTER_Object(ETHERNET_RMONSTATS_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ETHERNET_RMONSTATS_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ETHERNET_ROOT ".RMONStatsNumberOfEntries", ETHERNET_RMONSTATS_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_RMONSTATS_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_RMONSTATS_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_RMONSTATS_ROOT ".{i}.VLANID", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_RMONSTATS_ROOT ".{i}.Queue", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_RMONSTATS_ROOT ".{i}.AllQueues", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.DropEvents", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Bytes", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Packets", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.BroadcastPackets", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.MulticastPackets", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.CRCErroredPackets", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.UndersizePackets", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.OversizePackets", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Packets64Bytes", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Packets65to127Bytes", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Packets128to255Bytes", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Packets256to511Bytes", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Packets512to1023Bytes", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_RMONSTATS_ROOT ".{i}.Packets1024to1518Bytes", uspd_get_value, DM_ULONG);
	char *unique_keys_rmon[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(ETHERNET_RMONSTATS_ROOT ".{i}", unique_keys_rmon, NUM_ELEM(unique_keys_rmon));

#define ETHERNET_LAG_ROOT "Device.Ethernet.LAG"
	err |= USP_REGISTER_Object(ETHERNET_LAG_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ETHERNET_LAG_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ETHERNET_ROOT ".LAGNumberOfEntries", ETHERNET_LAG_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ETHERNET_LAG_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.LowerLayers", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.MacAddress", uspd_get_value, DM_STRING);

	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(ETHERNET_LAG_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);

	char *unique_keys_lag[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(ETHERNET_LAG_ROOT ".{i}", unique_keys_lag, NUM_ELEM(unique_keys_lag));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_USB_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_USB_ROOT "Device.USB"
#define USB_INT_ROOT "Device.USB.Interface"
	err |= USP_REGISTER_Object(USB_INT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(USB_INT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_USB_ROOT ".InterfaceNumberOfEntries", USB_INT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(USB_INT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(USB_INT_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Upstream", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.MACAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.MaxBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Port", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_INT_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);

	char *unique_keys_usbint[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(USB_INT_ROOT ".{i}", unique_keys_usbint, NUM_ELEM(unique_keys_usbint));

#define USB_PORT_ROOT "Device.USB.Port"
	err |= USP_REGISTER_Object(USB_PORT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(USB_PORT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_USB_ROOT ".PortNumberOfEntries", USB_PORT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(USB_PORT_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_PORT_ROOT ".{i}.Standard", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_PORT_ROOT ".{i}.Type", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_PORT_ROOT ".{i}.Receptacle", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_PORT_ROOT ".{i}.Rate", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_PORT_ROOT ".{i}.Power", uspd_get_value, DM_STRING);

	char *unique_keys_usbport[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(USB_PORT_ROOT ".{i}", unique_keys_usbport, NUM_ELEM(unique_keys_usbport));

#define USB_HOSTS_ROOT "Device.USB.USBHosts"
#define USB_HOST_ROOT "Device.USB.USBHosts.Host"
	err |= USP_REGISTER_Object(USB_HOST_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(USB_HOST_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(USB_HOSTS_ROOT ".HostNumberOfEntries", USB_HOST_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(USB_HOST_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_HOST_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_HOST_ROOT ".{i}.Type", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(USB_HOST_ROOT ".{i}.PowerManagementEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_HOST_ROOT ".{i}.USBVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_HOST_ROOT ".{i}.Rate", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(USB_HOST_ROOT ".{i}.Power", uspd_get_value, DM_STRING);


#define HOST_DEVICE_ROOT "Device.USB.USBHosts.Host.{i}.Device"
	err |= USP_REGISTER_Object(HOST_DEVICE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(HOST_DEVICE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(USB_HOST_ROOT ".{i}.DeviceNumberOfEntries", HOST_DEVICE_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.DeviceNumber", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.USBVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.DeviceClass", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.DeviceSubClass", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.DeviceVersion", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.DeviceProtocol", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.ProductID", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.VendorID", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.Manufacturer", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.ProductClass", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.SerialNumber", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.Port", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.USBPort", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.Rate", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.Parent", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.MaxChildren", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.IsSuspended", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_ROOT ".{i}.IsSelfPowered", uspd_get_value, DM_BOOL);

#define HOST_DEVICE_CFG_ROOT "Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration"
	err |= USP_REGISTER_Object(HOST_DEVICE_CFG_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(HOST_DEVICE_CFG_ROOT ".{i}.Alias", NULL);

	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_CFG_ROOT ".{i}.ConfigurationNumber", uspd_get_value, DM_UINT);

#define HOST_DEVICE_CFG_INT_ROOT "Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}.Interface"
	err |= USP_REGISTER_Object(HOST_DEVICE_CFG_INT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(HOST_DEVICE_CFG_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(HOST_DEVICE_CFG_ROOT ".{i}.InterfaceNumberOfEntries", HOST_DEVICE_CFG_INT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_CFG_INT_ROOT ".{i}.InterfaceNumber", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_CFG_INT_ROOT ".{i}.InterfaceClass", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_CFG_INT_ROOT ".{i}.InterfaceSubClass", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOST_DEVICE_CFG_INT_ROOT ".{i}.InterfaceProtocol", uspd_get_value, DM_STRING);

	char *unique_keys_usbhost[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(USB_HOST_ROOT ".{i}", unique_keys_usbhost, NUM_ELEM(unique_keys_usbhost));
	char *unique_keys_hostdevice[] = { "DeviceNumber" };
	err |= USP_REGISTER_Object_UniqueKey(HOST_DEVICE_ROOT ".{i}", unique_keys_hostdevice, NUM_ELEM(unique_keys_hostdevice));
	char *unique_keys_hostdevicecfg[] = { "ConfigurationNumber" };
	err |= USP_REGISTER_Object_UniqueKey(HOST_DEVICE_CFG_ROOT ".{i}", unique_keys_hostdevicecfg, NUM_ELEM(unique_keys_hostdevicecfg));
	char *unique_keys_hostdevicecfgint[] = { "InterfaceNumber" };
	err |= USP_REGISTER_Object_UniqueKey(HOST_DEVICE_CFG_INT_ROOT ".{i}", unique_keys_hostdevicecfgint, NUM_ELEM(unique_keys_hostdevicecfgint));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_HPNA_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_MoCA_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_Ghn_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_HomePlug_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_UPA_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_WiFi_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_WIFI_ROOT "Device.WiFi"
	err |= USP_REGISTER_SyncOperation(DEVICE_WIFI_ROOT ".Reset()", uspd_operate_sync);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_ROOT ".ResetCounter", uspd_get_value, DM_UINT);

#define WIFI_RADIO_ROOT "Device.WiFi.Radio"
	err |= USP_REGISTER_Object(WIFI_RADIO_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(WIFI_RADIO_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_WIFI_ROOT ".RadioNumberOfEntries", WIFI_RADIO_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Upstream", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.MaxBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.SupportedFrequencyBands", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.OperatingFrequencyBand", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.SupportedStandards", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.OperatingStandards", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.PossibleChannels", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.ChannelsInUse", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.Channel", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.AutoChannelSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.AutoChannelEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.AutoChannelRefreshPeriod", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.ChannelLastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.ChannelLastSelectionReason", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.MaxSupportedSSIDs", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.MaxSupportedAssociations", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.FirmwareVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.SupportedOperatingChannelBandwidths", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.OperatingChannelBandwidth", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.CurrentOperatingChannelBandwidth", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.ExtensionChannel", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.GuardInterval", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.MCS", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.TransmitPowerSupported", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.TransmitPower", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.IEEE80211hSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.IEEE80211hEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.RegulatoryDomain", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.RetryLimit", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.FragmentationThreshold", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.RTSThreshold", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.LongRetryLimit", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.BeaconPeriod", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.DTIMPeriod", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.PacketAggregationEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.PreambleType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.BasicDataTransmitRates", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.OperationalDataTransmitRates", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.SupportedDataTransmitRates", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.PLCPErrorCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.FCSErrorCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.InvalidMACCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.PacketsOtherReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.Noise", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.TotalChannelChangeCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.ManualChannelChangeCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.AutoStartupChannelChangeCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.AutoUserChannelChangeCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.AutoRefreshChannelChangeCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.AutoDynamicChannelChangeCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_RADIO_ROOT ".{i}.Stats.AutoDFSChannelChangeCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.X_IOPSYS_EU_DFSEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_RADIO_ROOT ".{i}.X_IOPSYS_EU_MaxAssociations", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_radio[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(WIFI_RADIO_ROOT ".{i}", unique_keys_radio, NUM_ELEM(unique_keys_radio));

#define WIFI_SSID_ROOT "Device.WiFi.SSID"
	err |= USP_REGISTER_Object(WIFI_SSID_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(WIFI_SSID_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_WIFI_ROOT ".SSIDNumberOfEntries", WIFI_SSID_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_SSID_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.LastChange", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_SSID_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.BSSID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.MACAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_SSID_ROOT ".{i}.SSID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Upstream", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.RetransCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.FailedRetransCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.RetryCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.MultipleRetryCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.ACKFailureCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.AggregatedPacketCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_SSID_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite("Device.WiFi.X_IOPSYS_EU_Bandsteering_Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	char *unique_keys_ssid[] = { "Name", "BSSID" };
	err |= USP_REGISTER_Object_UniqueKey(WIFI_SSID_ROOT ".{i}", unique_keys_ssid, NUM_ELEM(unique_keys_ssid));

#define WIFI_AP_ROOT "Device.WiFi.AccessPoint"
	err |= USP_REGISTER_Object(WIFI_AP_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(WIFI_AP_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_WIFI_ROOT ".AccessPointNumberOfEntries", WIFI_AP_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_AP_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.SSIDReference", uspd_get_value,uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.SSIDAdvertisementEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.MACAddressControlEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.RetryLimit", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_AP_ROOT ".{i}.WMMCapability", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_AP_ROOT ".{i}.UAPSDCapability", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.WMMEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.UAPSDEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.MaxAssociatedDevices", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.IsolationEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.AllowedMACAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.MaxAllowedAssociations", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_AP_ROOT ".{i}.Security.ModesSupported", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.ModeEnabled", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.WEPKey", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.PreSharedKey", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.KeyPassphrase", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.RekeyingInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.RadiusServerIPAddr", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.SecondaryRadiusServerIPAddr", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.RadiusServerPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.SecondaryRadiusServerPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.RadiusSecret", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.SecondaryRadiusSecret", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.MFPConfig", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Security.X_IOPSYS_EU_WEPKeyIndex", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.WPS.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_AP_ROOT ".{i}.WPS.ConfigMethodsSupported", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.WPS.ConfigMethodsEnabled", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_AP_ROOT ".{i}.WPS.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_AP_ROOT ".{i}.WPS.Version", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.WPS.PIN", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Accounting.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Accounting.ServerIPAddr", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Accounting.SecondaryServerIPAddr", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Accounting.ServerPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Accounting.SecondaryServerPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Accounting.Secret", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Accounting.SecondarySecret", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.Accounting.InterimInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_AP_ROOT ".{i}.X_IOPSYS_EU_IEEE80211r.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	//err |= USP_REGISTER_SyncOperation(WIFI_AP_ROOT ".{i}.Security.Reset()", uspd_operate_sync);
	char *unique_keys_ap[] = { "SSIDReference" };
	err |= USP_REGISTER_Object_UniqueKey(WIFI_AP_ROOT ".{i}", unique_keys_ap, NUM_ELEM(unique_keys_ap));

#define AP_AD_ROOT WIFI_AP_ROOT".{i}.AssociatedDevice"
	err |= USP_REGISTER_Object(AP_AD_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_Param_NumEntries(WIFI_AP_ROOT ".{i}.AssociatedDeviceNumberOfEntries", AP_AD_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.MACAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.OperatingStandard", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.AuthenticationState", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.LastDataDownlinkRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.LastDataUplinkRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.AssociationTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.SignalStrength", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Noise", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Retransmissions", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Active", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Stats.RetransCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Stats.FailedRetransCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Stats.RetryCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AD_ROOT ".{i}.Stats.MultipleRetryCount", uspd_get_value, DM_UINT);
	char *unique_keys_ad[] = { "MACAddress" };
	err |= USP_REGISTER_Object_UniqueKey(AP_AD_ROOT ".{i}", unique_keys_ad, NUM_ELEM(unique_keys_ad));

#define AP_AC_ROOT WIFI_AP_ROOT".{i}.AC"
	err |= USP_REGISTER_Object(AP_AC_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	//err |= USP_REGISTER_DBParam_Alias(AP_AC_ROOT".{i}.Alias", NULL);

	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.AccessCategory", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(AP_AC_ROOT".{i}.AIFSN", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(AP_AC_ROOT".{i}.ECWMin", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(AP_AC_ROOT".{i}.ECWMax", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(AP_AC_ROOT".{i}.TxOpMax", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(AP_AC_ROOT".{i}.AckPolicy", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(AP_AC_ROOT".{i}.OutQLenHistogramIntervals", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(AP_AC_ROOT".{i}.OutQLenHistogramSampleInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.RetransCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(AP_AC_ROOT ".{i}.Stats.OutQLenHistogram", uspd_get_value, DM_STRING);
	char *unique_keys_ac[] = { "AccessCategory" };
	err |= USP_REGISTER_Object_UniqueKey(AP_AC_ROOT ".{i}", unique_keys_ac, NUM_ELEM(unique_keys_ac));

#define WIFI_EP_ROOT "Device.WiFi.EndPoint"
	err |= USP_REGISTER_Object(WIFI_EP_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(WIFI_EP_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_WIFI_ROOT ".EndPointNumberOfEntries", WIFI_EP_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.ProfileReference", uspd_get_value,uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.SSIDReference", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.Stats.LastDataDownlinkRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.Stats.LastDataUplinkRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.Stats.SignalStrength", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.Stats.Retransmissions", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.Security.ModesSupported", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.WPS.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.WPS.ConfigMethodsSupported", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.WPS.ConfigMethodsEnabled", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.WPS.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.WPS.Version", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.WPS.PIN", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_ep[] = { "SSIDReference" };
	err |= USP_REGISTER_Object_UniqueKey(WIFI_EP_ROOT ".{i}", unique_keys_ep, NUM_ELEM(unique_keys_ep));

	err |= USP_REGISTER_Object(WIFI_EP_ROOT ".{i}.Profile.{i}.", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(WIFI_EP_ROOT ".{i}.Profile.{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(WIFI_EP_ROOT ".{i}.ProfileNumberOfEntries", WIFI_EP_ROOT ".{i}.Profile.{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Profile.{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(WIFI_EP_ROOT ".{i}.Profile.{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Profile.{i}.SSID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Profile.{i}.Location", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Profile.{i}.Priority", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Profile.{i}.Security.ModeEnabled", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Profile.{i}.Security.WEPKey", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Profile.{i}.Security.PreSharedKey", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Profile.{i}.Security.KeyPassphrase", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(WIFI_EP_ROOT ".{i}.Profile.{i}.Security.MFPConfig", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_ep_profile[] = { "SSID" };
	err |= USP_REGISTER_Object_UniqueKey(WIFI_EP_ROOT ".{i}.Profile.{i}", unique_keys_ep_profile, NUM_ELEM(unique_keys_ep_profile));
#define EP_AC_ROOT WIFI_EP_ROOT".{i}.AC"
	err |= USP_REGISTER_Object(EP_AC_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	// err |= USP_REGISTER_DBParam_Alias(EP_AC_ROOT".{i}.Alias", NULL);

	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.AccessCategory", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(EP_AC_ROOT".{i}.AIFSN", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(EP_AC_ROOT".{i}.ECWMin", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(EP_AC_ROOT".{i}.ECWMax", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(EP_AC_ROOT".{i}.TxOpMax", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(EP_AC_ROOT".{i}.AckPolicy", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(EP_AC_ROOT".{i}.OutQLenHistogramIntervals", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(EP_AC_ROOT".{i}.OutQLenHistogramSampleInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.RetransCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(EP_AC_ROOT ".{i}.Stats.OutQLenHistogram", uspd_get_value, DM_STRING);
	char *unique_keys_ep_ac[] = { "AccessCategory" };
	err |= USP_REGISTER_Object_UniqueKey(EP_AC_ROOT ".{i}", unique_keys_ep_ac, NUM_ELEM(unique_keys_ep_ac));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_ZigBee_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_Bridging_init(void)
{
	int err = USP_ERR_OK;

#define DEVICE_BRIDGING_ROOT "Device.Bridging"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".MaxBridgeEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".MaxDBridgeEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".MaxQBridgeEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".MaxVLANEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".MaxProviderBridgeEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".MaxFilterEntries", uspd_get_value, DM_UINT);

#define BRIDGING_BRIDGE_ROOT "Device.Bridging.Bridge"
	err |= USP_REGISTER_Object(BRIDGING_BRIDGE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(BRIDGING_BRIDGE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_BRIDGING_ROOT ".BridgeNumberOfEntries", BRIDGING_BRIDGE_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Standard", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.X_IOPSYS_EU_AssociatedInterfaces", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	err |= USP_REGISTER_Object(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(BRIDGING_BRIDGE_ROOT ".{i}.PortNumberOfEntries", BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.ManagementPort", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Type", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.DefaultUserPriority", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.PriorityRegeneration", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.PortState", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.PVID", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.TPID", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.AcceptableFrameTypes", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.IngressFiltering", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.ServiceAccessPrioritySelection", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.PriorityTagging", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.PriorityCodePoint.PCPSelection", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.PriorityCodePoint.UseDEI", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.PriorityCodePoint.RequireDropEncoding", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.PriorityCodePoint.PCPEncoding", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}.PriorityCodePoint.PCPDecoding", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	err |= USP_REGISTER_Object(BRIDGING_BRIDGE_ROOT ".{i}.VLAN.{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(BRIDGING_BRIDGE_ROOT ".{i}.VLAN.{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(BRIDGING_BRIDGE_ROOT ".{i}.VLANNumberOfEntries", BRIDGING_BRIDGE_ROOT ".{i}.VLAN.{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.VLAN.{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.VLAN.{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.VLAN.{i}.VLANID", uspd_get_value, uspd_set_value, NULL, DM_INT);

	err |= USP_REGISTER_Object(BRIDGING_BRIDGE_ROOT ".{i}.VLANPort.{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(BRIDGING_BRIDGE_ROOT ".{i}.VLANPort.{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(BRIDGING_BRIDGE_ROOT ".{i}.VLANPortNumberOfEntries", BRIDGING_BRIDGE_ROOT ".{i}.VLANPort.{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.VLANPort.{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.VLANPort.{i}.VLAN", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.VLANPort.{i}.Port", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_BRIDGE_ROOT ".{i}.VLANPort.{i}.Untagged", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

#define BRIDGING_FILTER_ROOT "Device.Bridging.Filter"
	err |= USP_REGISTER_Object(BRIDGING_FILTER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(BRIDGING_FILTER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_BRIDGING_ROOT ".FilterNumberOfEntries", BRIDGING_FILTER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_FILTER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.Bridge", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DHCPType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.EthertypeFilterList", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.EthertypeFilterExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourceMACAddressFilterList", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourceMACAddressFilterExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestMACAddressFilterList", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestMACAddressFilterExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourceMACFromVendorClassIDFilter", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourceMACFromVendorClassIDFilterExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourceMACFromVendorClassIDMode", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestMACFromVendorClassIDFilter", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestMACFromVendorClassIDFilterExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestMACFromVendorClassIDMode", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestIP", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestIPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourceIP", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourceMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourceIPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.Protocol", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.ProtocolExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestPort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestPortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.DestPortExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourcePort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourcePortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_FILTER_ROOT ".{i}.SourcePortExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

#define BRIDGING_PROVIDER_ROOT "Device.Bridging.ProviderBridge"
	err |= USP_REGISTER_Object(BRIDGING_PROVIDER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(BRIDGING_PROVIDER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_BRIDGING_ROOT ".ProviderBridgeNumberOfEntries", BRIDGING_PROVIDER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_PROVIDER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(BRIDGING_PROVIDER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_PROVIDER_ROOT ".{i}.Type", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_PROVIDER_ROOT ".{i}.SVLANcomponent", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(BRIDGING_PROVIDER_ROOT ".{i}.CVLANcomponents", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_bridge[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(BRIDGING_BRIDGE_ROOT ".{i}", unique_keys_bridge, NUM_ELEM(unique_keys_bridge));
	char *unique_keys_bridge_port[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(BRIDGING_BRIDGE_ROOT ".{i}.Port.{i}", unique_keys_bridge_port, NUM_ELEM(unique_keys_bridge_port));
	char *unique_keys_bridge_vlan[] = { "VLANID" };
	err |= USP_REGISTER_Object_UniqueKey(BRIDGING_BRIDGE_ROOT ".{i}.VLAN.{i}", unique_keys_bridge_vlan, NUM_ELEM(unique_keys_bridge_vlan));
	char *unique_keys_bridge_vlan_port[] = { "VLAN", "Port" };
	err |= USP_REGISTER_Object_UniqueKey(BRIDGING_BRIDGE_ROOT ".{i}.VLANPort.{i}", unique_keys_bridge_vlan_port, NUM_ELEM(unique_keys_bridge_vlan_port));
	char *unique_keys_bridging_filter[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(BRIDGING_FILTER_ROOT ".{i}", unique_keys_bridging_filter, NUM_ELEM(unique_keys_bridging_filter));
	char *unique_keys_bridging_provider[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(BRIDGING_PROVIDER_ROOT ".{i}", unique_keys_bridging_provider, NUM_ELEM(unique_keys_bridging_provider));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_PPP_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_PPP_ROOT "Device.PPP"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PPP_ROOT ".SupportedNCPs", uspd_get_value, DM_STRING);
#define PPP_INT_ROOT "Device.PPP.Interface"
	err |= USP_REGISTER_Object(PPP_INT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(PPP_INT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_PPP_ROOT ".InterfaceNumberOfEntries", PPP_INT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.ConnectionStatus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.LastConnectionError", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.AutoDisconnectTime", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.IdleDisconnectTime", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.WarnDisconnectDelay", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.Username", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.Password", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.EncryptionProtocol", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.CompressionProtocol", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.AuthenticationProtocol", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.MaxMRUSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.CurrentMRUSize", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.ConnectionTrigger", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.LCPEcho", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.LCPEchoRetry", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.IPCPEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.IPv6CPEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.PPPoE.SessionID", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.PPPoE.ACName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.PPPoE.ServiceName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.IPCP.LocalIPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.IPCP.RemoteIPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.IPCP.DNSServers", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.IPCP.PassthroughEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(PPP_INT_ROOT ".{i}.IPCP.PassthroughDHCPPool", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.IPv6CP.LocalInterfaceIdentifier", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.IPv6CP.RemoteInterfaceIdentifier", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(PPP_INT_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);
	char *unique_keys_ppp_interface[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(PPP_INT_ROOT ".{i}", unique_keys_ppp_interface, NUM_ELEM(unique_keys_ppp_interface));
	err |= USP_REGISTER_SyncOperation(PPP_INT_ROOT ".{i}.Reset()", uspd_operate_sync);

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_IP_init(void)
{
	int err = USP_ERR_OK;

#define DEVICE_IP_ROOT "Device.IP"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_ROOT ".IPv4Capable", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_ROOT ".IPv4Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_ROOT ".IPv4Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_ROOT ".IPv6Capable", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_ROOT ".IPv6Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_ROOT ".IPv6Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_ROOT ".ULAPrefix", uspd_get_value, DM_STRING);

#define DEVICE_IP_INT_ROOT "Device.IP.Interface"
	err |= USP_REGISTER_Object(DEVICE_IP_INT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_IP_INT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_IP_ROOT ".InterfaceNumberOfEntries", DEVICE_IP_INT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.IPv4Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.IPv6Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.ULAEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.Router", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.MaxMTUSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Type", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.Loopback", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.AutoIPEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_SyncOperation(DEVICE_IP_INT_ROOT ".{i}.Reset()", uspd_operate_sync);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.UnicastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.UnicastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.MulticastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.BroadcastPacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.BroadcastPacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.UnknownProtoPacketsReceived", uspd_get_value, DM_UINT);

	char *unique_keys_interface[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_IP_INT_ROOT ".{i}", unique_keys_interface, NUM_ELEM(unique_keys_interface));

	//err |= USP_REGISTER_Param_NumEntries("Device.IP.Interface.{i}.TWAMPReflectorNumberOfEntries", DEVICE_IP_INT_ROOT ".{i}.TWAMPReflector.{i}");

#define IP_INT_IPv4_ROOT "Device.IP.Interface.{i}.IPv4Address"
	err |= USP_REGISTER_Object(IP_INT_IPv4_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(IP_INT_IPv4_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.IP.Interface.{i}.IPv4AddressNumberOfEntries", IP_INT_IPv4_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv4_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_INT_IPv4_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv4_ROOT ".{i}.IPAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv4_ROOT ".{i}.SubnetMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_INT_IPv4_ROOT ".{i}.AddressingType", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv4_ROOT ".{i}.X_IOPSYS_EU_FirewallEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	char *unique_keys_ipv4[] = { "IPAddress", "SubnetMask" };
	err |= USP_REGISTER_Object_UniqueKey(IP_INT_IPv4_ROOT ".{i}", unique_keys_ipv4, NUM_ELEM(unique_keys_ipv4));

#define IP_INT_IPv6_ROOT "Device.IP.Interface.{i}.IPv6Address"
	err |= USP_REGISTER_Object(IP_INT_IPv6_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(IP_INT_IPv6_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.IP.Interface.{i}.IPv6AddressNumberOfEntries", IP_INT_IPv6_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_INT_IPv6_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_INT_IPv6_ROOT ".{i}.IPAddressStatus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6_ROOT ".{i}.IPAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_INT_IPv6_ROOT ".{i}.Origin", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6_ROOT ".{i}.Prefix", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6_ROOT ".{i}.PreferredLifetime", uspd_get_value, uspd_set_value, NULL, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6_ROOT ".{i}.ValidLifetime", uspd_get_value, uspd_set_value, NULL, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6_ROOT ".{i}.Anycast", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

	char *unique_keys_ipv6[] = { "IPAddress", "Prefix" };
	err |= USP_REGISTER_Object_UniqueKey(IP_INT_IPv6_ROOT ".{i}", unique_keys_ipv6, NUM_ELEM(unique_keys_ipv6));

#define IP_INT_IPv6Prefix_ROOT "Device.IP.Interface.{i}.IPv6Prefix"
	err |= USP_REGISTER_Object(IP_INT_IPv6Prefix_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(IP_INT_IPv6Prefix_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.IP.Interface.{i}.IPv6PrefixNumberOfEntries", IP_INT_IPv6Prefix_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6Prefix_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_INT_IPv6Prefix_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_INT_IPv6Prefix_ROOT ".{i}.PrefixStatus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6Prefix_ROOT ".{i}.Prefix", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_INT_IPv6Prefix_ROOT ".{i}.Origin", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6Prefix_ROOT ".{i}.StaticType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6Prefix_ROOT ".{i}.ParentPrefix", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6Prefix_ROOT ".{i}.ChildPrefixBits", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6Prefix_ROOT ".{i}.Onlink", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6Prefix_ROOT ".{i}.Autonomous", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6Prefix_ROOT ".{i}.PreferredLifetime", uspd_get_value, uspd_set_value, NULL, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_INT_IPv6Prefix_ROOT ".{i}.ValidLifetime", uspd_get_value, uspd_set_value, NULL, DM_DATETIME);

	char *unique_keys_ipv6prefix[] = { "Prefix" };
	err |= USP_REGISTER_Object_UniqueKey(IP_INT_IPv6Prefix_ROOT ".{i}", unique_keys_ipv6prefix, NUM_ELEM(unique_keys_ipv6prefix));

#define IP_ACTIVEPORT_ROOT "Device.IP.ActivePort"
	err |= USP_REGISTER_Object(IP_ACTIVEPORT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(IP_ACTIVEPORT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_IP_ROOT ".ActivePortNumberOfEntries", IP_ACTIVEPORT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(IP_ACTIVEPORT_ROOT ".{i}.LocalIPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_ACTIVEPORT_ROOT ".{i}.LocalPort", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_ACTIVEPORT_ROOT ".{i}.RemoteIPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_ACTIVEPORT_ROOT ".{i}.RemotePort", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_ACTIVEPORT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);

	char *unique_keys_activeport[] = { "LocalIPAddress", "LocalPort", "RemoteIPAddress", "RemotePort"};
	err |= USP_REGISTER_Object_UniqueKey(IP_ACTIVEPORT_ROOT ".{i}", unique_keys_activeport, NUM_ELEM(unique_keys_activeport));

#define IP_DIAG_ROOT "Device.IP.Diagnostics"
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv4PingSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv6PingSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv4TraceRouteSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv6TraceRouteSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv4DownloadDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv6DownloadDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv4UploadDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv6UploadDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv4UDPEchoDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv6UDPEchoDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv4ServerSelectionDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".IPv6ServerSelectionDiagnosticsSupported", uspd_get_value, DM_BOOL);

	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".ServerSelectionDiagnostics.AverageResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DIAG_ROOT ".ServerSelectionDiagnostics.DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".ServerSelectionDiagnostics.FastestHost", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".ServerSelectionDiagnostics.IPAddressUsed", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DIAG_ROOT ".ServerSelectionDiagnostics.HostList", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DIAG_ROOT ".ServerSelectionDiagnostics.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".ServerSelectionDiagnostics.MaximumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".ServerSelectionDiagnostics.MinimumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DIAG_ROOT ".ServerSelectionDiagnostics.NumberOfRepetitions", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DIAG_ROOT ".ServerSelectionDiagnostics.Port", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DIAG_ROOT ".ServerSelectionDiagnostics.Protocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DIAG_ROOT ".ServerSelectionDiagnostics.ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DIAG_ROOT ".ServerSelectionDiagnostics.Timeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".DownloadTransports", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".DownloadDiagnosticMaxConnections", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".DownloadDiagnosticsMaxIncrementalResult", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".UploadTransports", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".UploadDiagnosticMaxConnections", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DIAG_ROOT ".UploadDiagnosticsMaxIncrementalResult", uspd_get_value, DM_UINT);

#define IP_IPPING_ROOT "Device.IP.Diagnostics.IPPing"
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_IPPING_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_IPPING_ROOT ".ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_IPPING_ROOT ".Host", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_IPPING_ROOT ".NumberOfRepetitions", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_IPPING_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_IPPING_ROOT ".Timeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_IPPING_ROOT ".DataBlockSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_IPPING_ROOT ".DSCP", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_IPPING_ROOT ".IPAddressUsed", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_IPPING_ROOT ".SuccessCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_IPPING_ROOT ".FailureCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_IPPING_ROOT ".AverageResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_IPPING_ROOT ".MinimumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_IPPING_ROOT ".MaximumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_IPPING_ROOT ".AverageResponseTimeDetailed", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_IPPING_ROOT ".MinimumResponseTimeDetailed", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_IPPING_ROOT ".MaximumResponseTimeDetailed", uspd_get_value, DM_UINT);

#define DEVICE_IP_TDIAG_ROOT "Device.IP.Diagnostics.TraceRoute"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".Host", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".NumberOfTries", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".Timeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".DataBlockSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".DSCP", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".MaxHopCount", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_TDIAG_ROOT ".IPAddressUsed", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_TDIAG_ROOT ".ResponseTime", uspd_get_value, DM_UINT);
	// err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_TDIAG_ROOT ".RouteHopsNumberOfEntries", uspd_get_value, DM_UINT);


#define IP_DDIAG_ROOT "Device.IP.Diagnostics.DownloadDiagnostics"
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".DownloadURL", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".DSCP", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".EthernetPriority", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".TimeBasedTestDuration", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".TimeBasedTestMeasurementInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".TimeBasedTestMeasurementOffset", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".NumberOfConnections", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IP_DDIAG_ROOT ".EnablePerConnectionResults", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".IPAddressUsed", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".ROMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".BOMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".EOMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".TestBytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".TotalBytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".TotalBytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".TestBytesReceivedUnderFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".TotalBytesReceivedUnderFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".TotalBytesSentUnderFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".PeriodOfFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".TCPOpenRequestTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(IP_DDIAG_ROOT ".TCPOpenResponseTime", uspd_get_value, DM_DATETIME);
	// err |= USP_REGISTER_Param_NumEntries("Device.IP.Diagnostics.DownloadDiagnostics.PerConnectionResultNumberOfEntries", IP_DDIAG_ROOT ".PerConnectionResult.{i}");


#define DEVICE_IP_DIAG_UCONFIG_ROOT "Device.IP.Diagnostics.UDPEchoConfig"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".SourceIPAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".UDPPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".EchoPlusEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".EchoPlusSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".PacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".PacketsResponded", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".BytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".BytesResponded", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".TimeFirstPacketReceived", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".TimeLastPacketReceived", uspd_get_value, DM_DATETIME);

#define DEVICE_IP_DIAG_UECHO_ROOT "Device.IP.Diagnostics.UDPEchoDiagnostics"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UECHO_ROOT ".AverageResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".DSCP", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".DataBlockSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UECHO_ROOT ".FailureCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".Host", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".InterTransmissionTime", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UECHO_ROOT ".MaximumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UECHO_ROOT ".MinimumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".NumberOfRepetitions", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".Port", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UECHO_ROOT ".SuccessCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".Timeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UECHO_ROOT ".EnableIndividualPacketResults", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UECHO_ROOT ".IPAddressUsed", uspd_get_value, DM_STRING);

#define DEVICE_IP_DIAG_UDIAG_ROOT "Device.IP.Diagnostics.UploadDiagnostics"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".BOMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".DSCP", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".TimeBasedTestDuration", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".TimeBasedTestMeasurementInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".TimeBasedTestMeasurementOffset", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".EOMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".EnablePerConnectionResults", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".EthernetPriority", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".NumberOfConnections", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".IPAddressUsed", uspd_get_value, DM_STRING);

	//err |= USP_REGISTER_Param_NumEntries(DEVICE_IP_DIAG_UDIAG_ROOT ".PerConnectionResultNumberOfEntries", DEVICE_IP_DIAG_UDIAG_ROOT ".PerConnectionResult.{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".PeriodOfFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".ROMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".TCPOpenRequestTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".TCPOpenResponseTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".TestBytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".TestBytesSentUnderFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".TestFileLength", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".TotalBytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".TotalBytesReceivedUnderFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".TotalBytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".TotalBytesSentUnderFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".UploadURL", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_LLDP_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_IPsec_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_IPSEC_ROOT "Device.IPsec"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IPSEC_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".AHSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".IKEv2SupportedEncryptionAlgorithms", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".ESPSupportedEncryptionAlgorithms", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".IKEv2SupportedPseudoRandomFunctions", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".SupportedIntegrityAlgorithms", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".SupportedDiffieHellmanGroupTransforms", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".MaxFilterEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".MaxProfileEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.NegotiationFailures", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.UnknownSPIErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.DecryptionErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.IntegrityErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.ReplayErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.PolicyErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IPSEC_ROOT ".Stats.OtherReceiveErrors", uspd_get_value, DM_UINT);

#define IPSEC_FILTER_ROOT "Device.IPsec.Filter"
	err |= USP_REGISTER_Object(IPSEC_FILTER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(IPSEC_FILTER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_IPSEC_ROOT ".FilterNumberOfEntries", IPSEC_FILTER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_FILTER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.AllInterfaces", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.DestIP", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.DestMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.DestIPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.SourceIP", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.SourceMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.SourceIPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.Protocol", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.ProtocolExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.DestPort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.DestPortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.DestPortExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.SourcePort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.SourcePortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.SourcePortExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.ProcessingChoice", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_FILTER_ROOT ".{i}.Profile", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define IPSEC_PROFILE_ROOT "Device.IPsec.Profile"
	err |= USP_REGISTER_Object(IPSEC_PROFILE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(IPSEC_PROFILE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_IPSEC_ROOT ".ProfileNumberOfEntries", IPSEC_PROFILE_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.MaxChildSAs", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.RemoteEndpoints", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.ForwardingPolicy", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.Protocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2AuthenticationMethod", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2AllowedEncryptionAlgorithms", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.ESPAllowedEncryptionAlgorithms", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2AllowedPseudoRandomFunctions", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2AllowedIntegrityAlgorithms", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.AHAllowedIntegrityAlgorithms", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.ESPAllowedIntegrityAlgorithms", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2AllowedDiffieHellmanGroupTransforms", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2DeadPeerDetectionTimeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2NATTKeepaliveTimeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.AntiReplayWindowSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.DoNotFragment", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.DSCPMarkPolicy", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2SATrafficLimit", uspd_get_value, uspd_set_value, NULL, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2SATimeLimit", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.IKEv2SAExpiryAction", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.ChildSATrafficLimit", uspd_get_value, uspd_set_value, NULL, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.ChildSATimeLimit", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPSEC_PROFILE_ROOT ".{i}.ChildSAExpiryAction", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define PROFILE_SCPATTR_ROOT "Device.IPsec.Profile.{i}.SentCPAttr"
	err |= USP_REGISTER_Object(PROFILE_SCPATTR_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(PROFILE_SCPATTR_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(IPSEC_PROFILE_ROOT ".{i}.SentCPAttrNumberOfEntries", PROFILE_SCPATTR_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(PROFILE_SCPATTR_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(PROFILE_SCPATTR_ROOT ".{i}.Type", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(PROFILE_SCPATTR_ROOT ".{i}.Value", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define IPSEC_TUNNEL_ROOT "Device.IPsec.Tunnel"
	err |= USP_REGISTER_Object(IPSEC_TUNNEL_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(IPSEC_TUNNEL_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_IPSEC_ROOT ".TunnelNumberOfEntries", IPSEC_TUNNEL_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_TUNNEL_ROOT ".{i}.TunnelInterface", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_TUNNEL_ROOT ".{i}.TunneledInterface", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_TUNNEL_ROOT ".{i}.Filters", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_TUNNEL_ROOT ".{i}.Stats.DecryptionErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_TUNNEL_ROOT ".{i}.Stats.IntegrityErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_TUNNEL_ROOT ".{i}.Stats.ReplayErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_TUNNEL_ROOT ".{i}.Stats.PolicyErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_TUNNEL_ROOT ".{i}.Stats.OtherReceiveErrors", uspd_get_value, DM_UINT);

#define IPSEC_IKEv2SA_ROOT "Device.IPsec.IKEv2SA"
	err |= USP_REGISTER_Object(IPSEC_IKEv2SA_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(IPSEC_IKEv2SA_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_IPSEC_ROOT ".IKEv2SANumberOfEntries", IPSEC_IKEv2SA_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Tunnel", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.LocalAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.RemoteAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.EncryptionAlgorithm", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.EncryptionKeyLength", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.PseudoRandomFunction", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.IntegrityAlgorithm", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.DiffieHellmanGroupTransform", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.CreationTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.NATDetected", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Stats.DecryptionErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Stats.IntegrityErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_ROOT ".{i}.Stats.OtherReceiveErrors", uspd_get_value, DM_UINT);

#define IPSEC_IKEv2SA_RCPATTR_ROOT "Device.IPsec.IKEv2SA.{i}.ReceivedCPAttr"
	err |= USP_REGISTER_Object(IPSEC_IKEv2SA_RCPATTR_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	//err |= USP_REGISTER_DBParam_Alias(IPSEC_IKEv2SA_RCPATTR_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(IPSEC_IKEv2SA_ROOT ".{i}.ReceivedCPAttrNumberOfEntries", IPSEC_IKEv2SA_RCPATTR_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_RCPATTR_ROOT ".{i}.Type", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_RCPATTR_ROOT ".{i}.Value", uspd_get_value, DM_STRING);

#define IPSEC_IKEv2SA_CHILDSA_ROOT "Device.IPsec.IKEv2SA.{i}.ChildSA"
	err |= USP_REGISTER_Object(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(IPSEC_IKEv2SA_ROOT ".{i}.ChildSANumberOfEntries", IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.InboundSPI", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.OutboundSPI", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.CreationTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.DecryptionErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.IntegrityErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.ReplayErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.PolicyErrors", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}.Stats.OtherReceiveErrors", uspd_get_value, DM_UINT);

	char *unique_keys_ipsecfilter[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(IPSEC_FILTER_ROOT ".{i}", unique_keys_ipsecfilter, NUM_ELEM(unique_keys_ipsecfilter));
	char *unique_keys_ipsecprofile[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(IPSEC_PROFILE_ROOT ".{i}", unique_keys_ipsecprofile, NUM_ELEM(unique_keys_ipsecprofile));
	char *unique_keys_profilescpattr[] = { "Type" };
	err |= USP_REGISTER_Object_UniqueKey(PROFILE_SCPATTR_ROOT ".{i}", unique_keys_profilescpattr, NUM_ELEM(unique_keys_profilescpattr));
	char *unique_keys_ipsectunnel[] = { "TunnelInterface", "TunneledInterface" };
	err |= USP_REGISTER_Object_UniqueKey(IPSEC_TUNNEL_ROOT ".{i}", unique_keys_ipsectunnel, NUM_ELEM(unique_keys_ipsectunnel));
	char *unique_keys_ipsecIKEv2SA[] = { "Tunnel" };
	err |= USP_REGISTER_Object_UniqueKey(IPSEC_IKEv2SA_ROOT ".{i}", unique_keys_ipsecIKEv2SA, NUM_ELEM(unique_keys_ipsecIKEv2SA));
	char *unique_keys_IKEv2SAchildsa[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(IPSEC_IKEv2SA_CHILDSA_ROOT ".{i}", unique_keys_IKEv2SAchildsa, NUM_ELEM(unique_keys_IKEv2SAchildsa));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_GRE_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_GRE_ROOT "Device.GRE"
#define GRE_TUNNEL_ROOT "Device.GRE.Tunnel"
	err |= USP_REGISTER_Object(GRE_TUNNEL_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(GRE_TUNNEL_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_GRE_ROOT ".TunnelNumberOfEntries", GRE_TUNNEL_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_ROOT ".{i}.RemoteEndpoints", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_ROOT ".{i}.KeepAlivePolicy", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_ROOT ".{i}.KeepAliveTimeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_ROOT ".{i}.KeepAliveThreshold", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_ROOT ".{i}.DeliveryHeaderProtocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_ROOT ".{i}.DefaultDSCPMark", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.ConnectedRemoteEndpoint", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.Stats.KeepAliveSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.Stats.KeepAliveReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);

#define GRE_TUNNEL_INTERFACE "Device.GRE.Tunnel.{i}.Interface"
	err |= USP_REGISTER_Object(GRE_TUNNEL_INTERFACE ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(GRE_TUNNEL_INTERFACE ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(GRE_TUNNEL_ROOT ".{i}.InterfaceNumberOfEntries", GRE_TUNNEL_INTERFACE ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_INTERFACE ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_INTERFACE ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_INTERFACE ".{i}.ProtocolIdOverride", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_INTERFACE ".{i}.UseChecksum", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_INTERFACE ".{i}.KeyIdentifierGenerationPolicy", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_INTERFACE ".{i}.KeyIdentifier", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_TUNNEL_INTERFACE ".{i}.UseSequenceNumber", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Stats.DiscardChecksumReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_TUNNEL_INTERFACE ".{i}.Stats.DiscardSequenceNumberReceived", uspd_get_value, DM_UINT);

#define GRE_FILTER_ROOT "Device.GRE.Filter"
	err |= USP_REGISTER_Object(GRE_FILTER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(GRE_FILTER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_GRE_ROOT ".FilterNumberOfEntries", GRE_FILTER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_FILTER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(GRE_FILTER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_FILTER_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_FILTER_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_FILTER_ROOT ".{i}.AllInterfaces", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_FILTER_ROOT ".{i}.VLANIDCheck", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_FILTER_ROOT ".{i}.VLANIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(GRE_FILTER_ROOT ".{i}.DSCPMarkPolicy", uspd_get_value, uspd_set_value, NULL, DM_INT);

	char *unique_keys_gretunnel[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(GRE_TUNNEL_ROOT ".{i}", unique_keys_gretunnel, NUM_ELEM(unique_keys_gretunnel));
	char *unique_keys_gretunnelint[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(GRE_TUNNEL_INTERFACE ".{i}", unique_keys_gretunnelint, NUM_ELEM(unique_keys_gretunnelint));
	char *unique_keys_grefilter[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(GRE_FILTER_ROOT ".{i}", unique_keys_grefilter, NUM_ELEM(unique_keys_grefilter));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_L2TPv3_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_VXLAN_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_VXLAN_ROOT "Device.VXLAN"
#define VXLAN_TUNNEL_ROOT "Device.VXLAN.Tunnel"
	err |= USP_REGISTER_Object(VXLAN_TUNNEL_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(VXLAN_TUNNEL_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_VXLAN_ROOT ".TunnelNumberOfEntries", VXLAN_TUNNEL_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_ROOT ".{i}.RemoteEndpoints", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_ROOT ".{i}.KeepAlivePolicy", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_ROOT ".{i}.KeepAliveTimeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_ROOT ".{i}.KeepAliveThreshold", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_ROOT ".{i}.DeliveryHeaderProtocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_ROOT ".{i}.DefaultDSCPMark", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.ConnectedRemoteEndpoint", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_ROOT ".{i}.SourcePort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_ROOT ".{i}.RemotePort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.Stats.KeepAliveSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.Stats.KeepAliveReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);

#define VXLAN_TUNNEL_INTERFACE "Device.VXLAN.Tunnel.{i}.Interface"
	err |= USP_REGISTER_Object(VXLAN_TUNNEL_INTERFACE ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(VXLAN_TUNNEL_INTERFACE ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(VXLAN_TUNNEL_ROOT ".{i}.InterfaceNumberOfEntries", VXLAN_TUNNEL_INTERFACE ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_INTERFACE ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_INTERFACE ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_TUNNEL_INTERFACE ".{i}.VNI", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Stats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Stats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Stats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Stats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Stats.DiscardChecksumReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_TUNNEL_INTERFACE ".{i}.Stats.DiscardSequenceNumberReceived", uspd_get_value, DM_UINT);

#define VXLAN_FILTER_ROOT "Device.VXLAN.Filter"
	err |= USP_REGISTER_Object(VXLAN_FILTER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(VXLAN_FILTER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_VXLAN_ROOT ".FilterNumberOfEntries", VXLAN_FILTER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_FILTER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(VXLAN_FILTER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_FILTER_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_FILTER_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_FILTER_ROOT ".{i}.AllInterfaces", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_FILTER_ROOT ".{i}.VLANIDCheck", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_FILTER_ROOT ".{i}.VLANIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(VXLAN_FILTER_ROOT ".{i}.DSCPMarkPolicy", uspd_get_value, uspd_set_value, NULL, DM_INT);

	char *unique_keys_vxlantunnel[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(VXLAN_TUNNEL_ROOT ".{i}", unique_keys_vxlantunnel, NUM_ELEM(unique_keys_vxlantunnel));
	char *unique_keys_vxlantunnelint[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(VXLAN_TUNNEL_INTERFACE ".{i}", unique_keys_vxlantunnelint, NUM_ELEM(unique_keys_vxlantunnelint));
	char *unique_keys_vxlanfilter[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(VXLAN_FILTER_ROOT ".{i}", unique_keys_vxlanfilter, NUM_ELEM(unique_keys_vxlanfilter));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_MAP_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_CaptivePortal_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_Routing_init(void)
{
	int err = USP_ERR_OK;

#define ROUTING_ROUTER_ROOT "Device.Routing.Router"
	err |= USP_REGISTER_Object(ROUTING_ROUTER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ROUTING_ROUTER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.Routing.RouterNumberOfEntries", ROUTING_ROUTER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	char *unique_keys_router[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(ROUTING_ROUTER_ROOT ".{i}", unique_keys_router, NUM_ELEM(unique_keys_router));

#define ROUTING_ROUTER_IPv4FORW_ROOT "Device.Routing.Router.{i}.IPv4Forwarding"
	err |= USP_REGISTER_Object(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(ROUTING_ROUTER_ROOT ".{i}.IPv4ForwardingNumberOfEntries", ROUTING_ROUTER_IPv4FORW_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.StaticRoute", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.DestIPAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.DestSubnetMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.ForwardingPolicy", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.GatewayIPAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.Origin", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}.ForwardingMetric", uspd_get_value, uspd_set_value, NULL, DM_INT);
	char *unique_keys_forw[] = { "DestIPAddress", "DestSubnetMask", "ForwardingPolicy", "GatewayIPAddress", "Interface", "ForwardingMetric" };
	err |= USP_REGISTER_Object_UniqueKey(ROUTING_ROUTER_IPv4FORW_ROOT ".{i}", unique_keys_forw, NUM_ELEM(unique_keys_forw));

#define ROUTING_ROUTER_IPv6FORW_ROOT "Device.Routing.Router.{i}.IPv6Forwarding"
	err |= USP_REGISTER_Object(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(ROUTING_ROUTER_ROOT ".{i}.IPv6ForwardingNumberOfEntries", ROUTING_ROUTER_IPv6FORW_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.DestIPPrefix", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.ForwardingPolicy", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.NextHop", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.Origin", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.ForwardingMetric", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}.ExpirationTime", uspd_get_value, DM_DATETIME);
	char *unique_keys_forw6[] = { "DestIPPrefix", "ForwardingPolicy", "NextHop", "Interface", "ForwardingMetric" };
	err |= USP_REGISTER_Object_UniqueKey(ROUTING_ROUTER_IPv6FORW_ROOT ".{i}", unique_keys_forw6, NUM_ELEM(unique_keys_forw6));

#define ROUTING_ROUTEINFO_ROOT "Device.Routing.RouteInformation"
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTEINFO_ROOT ".Enable", uspd_get_value, DM_BOOL);
#define ROUTING_ROUTEINFO_IS_ROOT ROUTING_ROUTEINFO_ROOT ".InterfaceSetting"
	err |= USP_REGISTER_Object(ROUTING_ROUTEINFO_IS_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(ROUTING_ROUTEINFO_IS_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(ROUTING_ROUTEINFO_ROOT ".InterfaceSettingNumberOfEntries", ROUTING_ROUTEINFO_IS_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTEINFO_IS_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTEINFO_IS_ROOT ".{i}.Interface", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTEINFO_IS_ROOT ".{i}.SourceRouter", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTEINFO_IS_ROOT ".{i}.PreferredRouteFlag", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTEINFO_IS_ROOT ".{i}.Prefix", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTING_ROUTEINFO_IS_ROOT ".{i}.RouteLifetime", uspd_get_value, DM_DATETIME);
	char *unique_keys_rinfo[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(ROUTING_ROUTEINFO_IS_ROOT ".{i}", unique_keys_rinfo, NUM_ELEM(unique_keys_rinfo));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}
	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_NeighborDiscovery_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_ND_ROOT "Device.NeighborDiscovery"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ND_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
#define ND_IS_ROOT DEVICE_ND_ROOT ".InterfaceSetting"
	err |= USP_REGISTER_Object(ND_IS_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ND_IS_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ND_ROOT ".InterfaceSettingNumberOfEntries", ND_IS_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ND_IS_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ND_IS_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ND_IS_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ND_IS_ROOT ".{i}.RetransTimer", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ND_IS_ROOT ".{i}.RtrSolicitationInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ND_IS_ROOT ".{i}.MaxRtrSolicitations", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ND_IS_ROOT ".{i}.NUDEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ND_IS_ROOT ".{i}.RSEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	char *unique_keys_nd[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(ND_IS_ROOT ".{i}", unique_keys_nd, NUM_ELEM(unique_keys_nd));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}
int vendor_RouterAdvertisement_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
#define DEVICE_ROUTER_AD_ROOT "Device.RouterAdvertisement"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ROUTER_AD_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
#define ROUTER_AD_IS_ROOT DEVICE_ROUTER_AD_ROOT ".InterfaceSetting"
	err |= USP_REGISTER_Object(ROUTER_AD_IS_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ROUTER_AD_IS_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ROUTER_AD_ROOT ".InterfaceSettingNumberOfEntries", ROUTER_AD_IS_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(ROUTER_AD_IS_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.ManualPrefixes", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.Prefixes", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.MaxRtrAdvInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.MinRtrAdvInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvDefaultLifetime", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvManagedFlag", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvOtherConfigFlag", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvMobileAgentFlag", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvPreferredRouterFlag", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvNDProxyFlag", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvLinkMTU", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvReachableTime", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvRetransTimer", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_ROOT ".{i}.AdvCurHopLimit", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_ra_is[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(ROUTER_AD_IS_ROOT ".{i}", unique_keys_ra_is, NUM_ELEM(unique_keys_ra_is));

#define ROUTER_AD_IS_OPTION_ROOT ROUTER_AD_IS_ROOT ".{i}.Option"
	err |= USP_REGISTER_Object(ROUTER_AD_IS_OPTION_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(ROUTER_AD_IS_OPTION_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(ROUTER_AD_IS_ROOT ".{i}.OptionNumberOfEntries", ROUTER_AD_IS_OPTION_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_OPTION_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_OPTION_ROOT ".{i}.Tag", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(ROUTER_AD_IS_OPTION_ROOT ".{i}.Value", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_ra_is_op[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(ROUTER_AD_IS_OPTION_ROOT ".{i}", unique_keys_ra_is_op, NUM_ELEM(unique_keys_ra_is_op));
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_IPv6rd_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_IPV6RD_ROOT "Device.IPv6rd"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IPV6RD_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
#define IPV6RD_IS_ROOT DEVICE_IPV6RD_ROOT ".InterfaceSetting"
	err |= USP_REGISTER_Object(IPV6RD_IS_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(IPV6RD_IS_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_IPV6RD_ROOT ".InterfaceSettingNumberOfEntries", IPV6RD_IS_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(IPV6RD_IS_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPV6RD_IS_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPV6RD_IS_ROOT ".{i}.BorderRelayIPv4Addresses", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPV6RD_IS_ROOT ".{i}.AllTrafficToBorderRelay", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPV6RD_IS_ROOT ".{i}.SPIPv6Prefix", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPV6RD_IS_ROOT ".{i}.IPv4MaskLength", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(IPV6RD_IS_ROOT ".{i}.AddressSource", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPV6RD_IS_ROOT ".{i}.TunnelInterface", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(IPV6RD_IS_ROOT ".{i}.TunneledInterface", uspd_get_value, DM_STRING);
	char *unique_keys_ipv6rd_is[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(IPV6RD_IS_ROOT ".{i}", unique_keys_ipv6rd_is, NUM_ELEM(unique_keys_ipv6rd_is));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_DSLite_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_QoS_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_QOS_ROOT "Device.QoS"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_QOS_ROOT ".MaxClassificationEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_QOS_ROOT ".MaxAppEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_QOS_ROOT ".MaxFlowEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_QOS_ROOT ".MaxPolicerEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_QOS_ROOT ".MaxQueueEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_QOS_ROOT ".MaxShaperEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_QOS_ROOT ".DefaultForwardingPolicy", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_QOS_ROOT ".DefaultTrafficClass", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_QOS_ROOT ".DefaultPolicer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_QOS_ROOT ".DefaultQueue", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_QOS_ROOT ".DefaultDSCPMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_QOS_ROOT ".DefaultEthernetPriorityMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_QOS_ROOT ".DefaultInnerEthernetPriorityMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_QOS_ROOT ".AvailableAppList", uspd_get_value, uspd_set_value, NULL, DM_STRING);
#define QOS_CLASSIFICATION_ROOT "Device.QoS.Classification"
	err |= USP_REGISTER_Object(QOS_CLASSIFICATION_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(QOS_CLASSIFICATION_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_QOS_ROOT ".ClassificationNumberOfEntries", QOS_CLASSIFICATION_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(QOS_CLASSIFICATION_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DHCPType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.AllInterfaces", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestIP", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestIPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceIP", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceIPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.Protocol", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.ProtocolExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestPort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestPortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestPortExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourcePort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourcePortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourcePortExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceMACAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceMACMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceMACExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestMACAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestMACMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestMACExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.Ethertype", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.EthertypeExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SSAP", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SSAPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DSAP", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DSAPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.LLCControl", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.LLCControlExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SNAPOUI", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SNAPOUIExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceVendorClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceVendorClassIDv6", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceVendorClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceVendorClassIDMode", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestVendorClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestVendorClassIDv6", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestVendorClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestVendorClassIDMode", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceClientID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceClientIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestClientID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestClientIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceUserClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceUserClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestUserClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestUserClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceVendorSpecificInfo", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceVendorSpecificInfoExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceVendorSpecificInfoEnterprise", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.SourceVendorSpecificInfoSubOption", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestVendorSpecificInfo", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestVendorSpecificInfoExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestVendorSpecificInfoEnterprise", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DestVendorSpecificInfoSubOption", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.TCPACK", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.TCPACKExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.IPLengthMin", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.IPLengthMax", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.IPLengthExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DSCPCheck", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DSCPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.DSCPMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.EthernetPriorityCheck", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.EthernetPriorityExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.EthernetPriorityMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.InnerEthernetPriorityCheck", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.InnerEthernetPriorityExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.InnerEthernetPriorityMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.EthernetDEICheck", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.EthernetDEIExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.VLANIDCheck", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.VLANIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.OutOfBandInfo", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.ForwardingPolicy", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.TrafficClass", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.Policer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_CLASSIFICATION_ROOT ".{i}.App", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_qos_class[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(QOS_CLASSIFICATION_ROOT ".{i}", unique_keys_qos_class, NUM_ELEM(unique_keys_qos_class));

#define QOS_APP_ROOT "Device.QoS.App"
	err |= USP_REGISTER_Object(QOS_APP_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(QOS_APP_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_QOS_ROOT ".AppNumberOfEntries", QOS_APP_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_APP_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(QOS_APP_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_APP_ROOT ".{i}.ProtocolIdentifier", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_APP_ROOT ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_APP_ROOT ".{i}.DefaultForwardingPolicy", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_APP_ROOT ".{i}.DefaultTrafficClass", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_APP_ROOT ".{i}.DefaultPolicer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_APP_ROOT ".{i}.DefaultDSCPMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_APP_ROOT ".{i}.DefaultEthernetPriorityMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_APP_ROOT ".{i}.DefaultInnerEthernetPriorityMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	char *unique_keys_qos_app[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(QOS_APP_ROOT ".{i}", unique_keys_qos_app, NUM_ELEM(unique_keys_qos_app));
#define QOS_FLOW_ROOT "Device.QoS.Flow"
	err |= USP_REGISTER_Object(QOS_FLOW_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(QOS_FLOW_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_QOS_ROOT ".FlowNumberOfEntries", QOS_FLOW_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(QOS_FLOW_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.Type", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.TypeParameters", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.App", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.ForwardingPolicy", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.TrafficClass", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.Policer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.DSCPMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.EthernetPriorityMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_FLOW_ROOT ".{i}.InnerEthernetPriorityMark", uspd_get_value, uspd_set_value, NULL, DM_INT);
	char *unique_keys_qos_flow[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(QOS_FLOW_ROOT ".{i}", unique_keys_qos_flow, NUM_ELEM(unique_keys_qos_flow));
#define QOS_POLICER_ROOT "Device.QoS.Policer"
	err |= USP_REGISTER_Object(QOS_POLICER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(QOS_POLICER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_QOS_ROOT ".PolicerNumberOfEntries", QOS_POLICER_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(QOS_POLICER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.CommittedRate", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.CommittedBurstSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.ExcessBurstSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.PeakRate", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.PeakBurstSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.MeterType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.PossibleMeterType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.ConformingAction", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.PartialConformingAction", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.NonConformingAction", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.TotalCountedPackets", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.TotalCountedBytes", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.ConformingCountedPackets", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.ConformingCountedBytes", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.PartiallyConformingCountedPackets", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.PartiallyConformingCountedBytes", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.NonConformingCountedPackets", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_POLICER_ROOT ".{i}.NonConformingCountedBytes", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_qos_policer[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(QOS_POLICER_ROOT ".{i}", unique_keys_qos_policer, NUM_ELEM(unique_keys_qos_policer));
#define QOS_QUEUE_ROOT "Device.QoS.Queue"
	err |= USP_REGISTER_Object(QOS_QUEUE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(QOS_QUEUE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_QOS_ROOT ".QueueNumberOfEntries", QOS_QUEUE_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(QOS_QUEUE_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.TrafficClasses", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.AllInterfaces", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(QOS_QUEUE_ROOT ".{i}.HardwareAssisted", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(QOS_QUEUE_ROOT ".{i}.BufferLength", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.Weight", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.Precedence", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.REDThreshold", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.REDPercentage", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.DropAlgorithm", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.SchedulerAlgorithm", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.ShapingRate", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUE_ROOT ".{i}.ShapingBurstSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_qos_queue[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(QOS_QUEUE_ROOT ".{i}", unique_keys_qos_queue, NUM_ELEM(unique_keys_qos_queue));
#define QOS_QUEUESTATS_ROOT "Device.QoS.QueueStats"
	err |= USP_REGISTER_Object(QOS_QUEUESTATS_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(QOS_QUEUESTATS_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_QOS_ROOT ".QueueStatsNumberOfEntries", QOS_QUEUESTATS_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUESTATS_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(QOS_QUEUESTATS_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUESTATS_ROOT ".{i}.Queue", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUESTATS_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUESTATS_ROOT ".{i}.OutputPackets", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUESTATS_ROOT ".{i}.OutputBytes", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUESTATS_ROOT ".{i}.DroppedPackets", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUESTATS_ROOT ".{i}.DroppedBytes", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUESTATS_ROOT ".{i}.QueueOccupancyPackets", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_QUEUESTATS_ROOT ".{i}.QueueOccupancyPercentage", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_qos_queuestats[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(QOS_QUEUESTATS_ROOT ".{i}", unique_keys_qos_queuestats, NUM_ELEM(unique_keys_qos_queuestats));
#define QOS_SHAPER_ROOT "Device.QoS.Shaper"
	err |= USP_REGISTER_Object(QOS_SHAPER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(QOS_SHAPER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_QOS_ROOT ".ShaperNumberOfEntries", QOS_SHAPER_ROOT".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_SHAPER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(QOS_SHAPER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_SHAPER_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_SHAPER_ROOT ".{i}.ShapingRate", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(QOS_SHAPER_ROOT ".{i}.ShapingBurstSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_qos_shaper[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(QOS_SHAPER_ROOT ".{i}", unique_keys_qos_shaper, NUM_ELEM(unique_keys_qos_shaper));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_LANConfigSecurity_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_Hosts_init(void)
{
	int err = USP_ERR_OK;
#define HOSTS_HOST_ROOT "Device.Hosts.Host"
	err |= USP_REGISTER_Object(HOSTS_HOST_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(HOSTS_HOST_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.Hosts.HostNumberOfEntries", HOSTS_HOST_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.PhysAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.IPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.AddressSource", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.DHCPClient", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.LeaseTimeRemaining", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.AssociatedDevice", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.Layer1Interface", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.Layer3Interface", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.VendorClassID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.ClientID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.UserClassID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.HostName", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.Active", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.ActiveLastChange", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.WANStats.BytesSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.WANStats.BytesReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.WANStats.PacketsSent", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.WANStats.PacketsReceived", uspd_get_value, DM_ULONG);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.WANStats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.WANStats.RetransCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.WANStats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.X_IOPSYS_EU_InterfaceType", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.X_IOPSYS_EU_LinkType", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_ROOT ".{i}.X_IOPSYS_EU_ifname", uspd_get_value, DM_STRING);
	char *unique_keys_hosts_host[] = { "PhysAddress" };
	err |= USP_REGISTER_Object_UniqueKey(HOSTS_HOST_ROOT ".{i}", unique_keys_hosts_host, NUM_ELEM(unique_keys_hosts_host));

#define HOSTS_HOST_IPV4_ROOT "Device.Hosts.Host.{i}.IPv4Address"
	err |= USP_REGISTER_Object(HOSTS_HOST_IPV4_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_Param_NumEntries(HOSTS_HOST_ROOT ".{i}.IPv4AddressNumberOfEntries", HOSTS_HOST_IPV4_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_IPV4_ROOT ".{i}.IPAddress", uspd_get_value, DM_STRING);
	char *unique_keys_hosts_host_ipv4[] = { "IPAddress" };
	err |= USP_REGISTER_Object_UniqueKey(HOSTS_HOST_IPV4_ROOT ".{i}", unique_keys_hosts_host_ipv4, NUM_ELEM(unique_keys_hosts_host_ipv4));

#define HOSTS_HOST_IPV6_ROOT "Device.Hosts.Host.{i}.IPv6Address"
	err |= USP_REGISTER_Object(HOSTS_HOST_IPV6_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_Param_NumEntries(HOSTS_HOST_ROOT ".{i}.IPv6AddressNumberOfEntries", HOSTS_HOST_IPV6_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(HOSTS_HOST_IPV6_ROOT ".{i}.IPAddress", uspd_get_value, DM_STRING);
	char *unique_keys_hosts_host_ipv6[] = { "IPAddress" };
	err |= USP_REGISTER_Object_UniqueKey(HOSTS_HOST_IPV6_ROOT ".{i}", unique_keys_hosts_host_ipv6, NUM_ELEM(unique_keys_hosts_host_ipv6));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_DNS_init(void)
{
	int err = USP_ERR_OK;

#define DEVICE_DNS_ROOT "Device.DNS"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DNS_ROOT ".SupportedRecordTypes", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_ROOT ".Client.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DNS_ROOT ".Client.Status", uspd_get_value, DM_STRING);

#define DNS_CLIENT_SERVER_ROOT "Device.DNS.Client.Server"
	err |= USP_REGISTER_Object(DNS_CLIENT_SERVER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DNS_CLIENT_SERVER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DNS_ROOT ".Client.ServerNumberOfEntries", DNS_CLIENT_SERVER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DNS_CLIENT_SERVER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_CLIENT_SERVER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DNS_CLIENT_SERVER_ROOT ".{i}.DNSServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DNS_CLIENT_SERVER_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_CLIENT_SERVER_ROOT ".{i}.Type", uspd_get_value, DM_STRING);
	char *unique_keys_dns_client_server[] = { "DNSServer" };
	err |= USP_REGISTER_Object_UniqueKey(DNS_CLIENT_SERVER_ROOT ".{i}", unique_keys_dns_client_server, NUM_ELEM(unique_keys_dns_client_server));

#define DNS_RELAY_ROOT "Device.DNS.Relay"
	err |= USP_REGISTER_VendorParam_ReadWrite(DNS_RELAY_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_RELAY_ROOT ".Status", uspd_get_value, DM_STRING);

#define DNS_RELAY_FW_ROOT DNS_RELAY_ROOT ".Forwarding"
	err |= USP_REGISTER_Object(DNS_RELAY_FW_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DNS_RELAY_FW_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DNS_RELAY_ROOT ".ForwardNumberOfEntries", DNS_RELAY_FW_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DNS_RELAY_FW_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_RELAY_FW_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DNS_RELAY_FW_ROOT ".{i}.DNSServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DNS_RELAY_FW_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_RELAY_FW_ROOT ".{i}.Type", uspd_get_value, DM_STRING);
	char *unique_keys_dns_relay_fw_server[] = { "DNSServer" };
	err |= USP_REGISTER_Object_UniqueKey(DNS_RELAY_FW_ROOT ".{i}", unique_keys_dns_relay_fw_server, NUM_ELEM(unique_keys_dns_relay_fw_server));

#define DEVICE_DNS_DIAGn_ROOT "Device.DNS.Diagnostics.NSLookupDiagnostics"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".HostName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".DNSServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".NumberOfRepetitions", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".Timeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DNS_DIAGn_ROOT ".SuccessCount", uspd_get_value, DM_UINT);
	// err |= USP_REGISTER_Param_NumEntries(DEVICE_DNS_DIAGn_ROOT ".ResultNumberOfEntries", DEVICE_DNS_DIAGn_ROOT".Result.{i}");


#define DNS_SD_ROOT "Device.DNS.SD"
	err |= USP_REGISTER_VendorParam_ReadWrite(DNS_SD_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DNS_SD_ROOT ".AdvertisedInterfaces", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

#define DNS_SD_SERVICE_ROOT DNS_SD_ROOT ".Service"
	err |= USP_REGISTER_Object(DNS_SD_SERVICE_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_Param_NumEntries(DNS_SD_ROOT ".ServiceNumberOfEntries", DNS_SD_SERVICE_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.InstanceName", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.ApplicationProtocol", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.TransportProtocol", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.Domain", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.Port", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.Target", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.LastUpdate", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.Host", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.TimeToLive", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.Priority", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_ROOT ".{i}.Weight", uspd_get_value, DM_UINT);
	char *unique_keys_dns_sd_service[] = { "InstanceName" };
	err |= USP_REGISTER_Object_UniqueKey(DNS_SD_SERVICE_ROOT ".{i}", unique_keys_dns_sd_service, NUM_ELEM(unique_keys_dns_sd_service));


#define DNS_SD_SERVICE_TR_ROOT DNS_SD_SERVICE_ROOT ".{i}.TextRecord"
	err |= USP_REGISTER_Object(DNS_SD_SERVICE_TR_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_Param_NumEntries(DNS_SD_SERVICE_ROOT ".{i}.TextRecordNumberOfEntries", DNS_SD_SERVICE_TR_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_TR_ROOT ".{i}.Key", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DNS_SD_SERVICE_TR_ROOT ".{i}.Value", uspd_get_value, DM_STRING);
	char *unique_keys_dns_sd_service_tr[] = { "Key" };
	err |= USP_REGISTER_Object_UniqueKey(DNS_SD_SERVICE_TR_ROOT ".{i}", unique_keys_dns_sd_service_tr, NUM_ELEM(unique_keys_dns_sd_service_tr));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_NAT_init(void)
{
	int err = USP_ERR_OK;
#define NAT_INT_ROOT "Device.NAT.InterfaceSetting"
	err |= USP_REGISTER_Object(NAT_INT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(NAT_INT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.NAT.InterfaceSettingNumberOfEntries", NAT_INT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_INT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(NAT_INT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_INT_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_nat_int[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(NAT_INT_ROOT ".{i}", unique_keys_nat_int, NUM_ELEM(unique_keys_nat_int));

#define NAT_PORTMAP_ROOT "Device.NAT.PortMapping"
	err |= USP_REGISTER_Object(NAT_PORTMAP_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(NAT_PORTMAP_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.NAT.PortMappingNumberOfEntries", NAT_PORTMAP_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(NAT_PORTMAP_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.AllInterfaces", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.LeaseDuration", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.RemoteHost", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.ExternalPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.ExternalPortEndRange", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.InternalPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.Protocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.InternalClient", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(NAT_PORTMAP_ROOT ".{i}.Description", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_nat_pm[] = { "RemoteHost", "ExternalPort", "Protocol" };
	err |= USP_REGISTER_Object_UniqueKey(NAT_PORTMAP_ROOT ".{i}", unique_keys_nat_pm, NUM_ELEM(unique_keys_nat_pm));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_PCP_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_DHCPv4_init(void)
{
	int err = USP_ERR_OK;

#define DEVICE_DHCPv4_ROOT "Device.DHCPv4"
#define DHCPv4_CLIENT_ROOT "Device.DHCPv4.Client"
	err |= USP_REGISTER_Object(DHCPv4_CLIENT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv4_CLIENT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv4_ROOT ".ClientNumberOfEntries", DHCPv4_CLIENT_ROOT ".{i}");

	err |= USP_REGISTER_SyncOperation(DHCPv4_CLIENT_ROOT ".{i}.Renew()", uspd_operate_sync);

	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_CLIENT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_CLIENT_ROOT ".{i}.DHCPStatus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_CLIENT_ROOT ".{i}.IPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_CLIENT_ROOT ".{i}.SubnetMask", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_CLIENT_ROOT ".{i}.IPRouters", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_CLIENT_ROOT ".{i}.DNSServers", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_CLIENT_ROOT ".{i}.LeaseTimeRemaining", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_CLIENT_ROOT ".{i}.DHCPServer", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_ROOT ".{i}.PassthroughEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_ROOT ".{i}.PassthroughDHCPPool", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_dhcp_client[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv4_CLIENT_ROOT ".{i}", unique_keys_dhcp_client, NUM_ELEM(unique_keys_dhcp_client));

#define DHCPv4_CLIENT_SENTOP_ROOT "Device.DHCPv4.Client.{i}.SentOption"
	err |= USP_REGISTER_Object(DHCPv4_CLIENT_SENTOP_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv4_CLIENT_SENTOP_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv4_CLIENT_ROOT ".{i}.SentOptionNumberOfEntries", DHCPv4_CLIENT_SENTOP_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_SENTOP_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_SENTOP_ROOT ".{i}.Tag", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_SENTOP_ROOT ".{i}.Value", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_sent[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv4_CLIENT_SENTOP_ROOT ".{i}", unique_keys_sent, NUM_ELEM(unique_keys_sent));

#define DHCPv4_CLIENT_REQ_ROOT "Device.DHCPv4.Client.{i}.ReqOption"
	err |= USP_REGISTER_Object(DHCPv4_CLIENT_REQ_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv4_CLIENT_REQ_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv4_CLIENT_ROOT ".{i}.ReqOptionNumberOfEntries", DHCPv4_CLIENT_REQ_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_REQ_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_REQ_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_CLIENT_REQ_ROOT ".{i}.Tag", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_CLIENT_REQ_ROOT ".{i}.Value", uspd_get_value, DM_STRING);

	char *unique_keys_req[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv4_CLIENT_REQ_ROOT ".{i}", unique_keys_req, NUM_ELEM(unique_keys_req));

#define DHCPV4_RELAY_ROOT "Device.DHCPv4.Relay"
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPV4_RELAY_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPV4_RELAY_ROOT ".Status", uspd_get_value, DM_STRING);
#define RELAY_FWD_ROOT "Device.DHCPv4.Relay.Forwarding"

	err |= USP_REGISTER_Object(RELAY_FWD_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(RELAY_FWD_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPV4_RELAY_ROOT ".ForwardingNumberOfEntries", "Device.DHCPv4.Relay.Forwarding.{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(RELAY_FWD_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.VendorClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.VendorClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.VendorClassIDMode", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.ClientID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.ClientIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.UserClassID", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.UserClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.Chaddr", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.ChaddrMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.ChaddrExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.LocallyServed", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(RELAY_FWD_ROOT ".{i}.DHCPServerIPAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_relay_fw[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(RELAY_FWD_ROOT ".{i}", unique_keys_relay_fw, NUM_ELEM(unique_keys_relay_fw));

#define DHCPv4_SERVER_ROOT "Device.DHCPv4.Server"
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
#define DHCPv4_SERVER_POOL "Device.DHCPv4.Server.Pool"
	err |= USP_REGISTER_Object(DHCPv4_SERVER_POOL ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv4_SERVER_POOL ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv4_SERVER_ROOT ".PoolNumberOfEntries", DHCPv4_SERVER_POOL ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_SERVER_POOL ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.VendorClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.VendorClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.VendorClassIDMode", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.ClientID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.ClientIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.UserClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.UserClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.Chaddr", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.ChaddrMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.MinAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.MaxAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.ReservedAddresses", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.SubnetMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.DNSServers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.DomainName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.IPRouters", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.LeaseTime", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL ".{i}.X_IOPSYS_EU_DHCPServerConfigurable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	char *unique_keys_v4_srv_pool[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv4_SERVER_POOL ".{i}", unique_keys_v4_srv_pool, NUM_ELEM(unique_keys_v4_srv_pool));

#define DHCPv4_SERVER_POOL_STATIC "Device.DHCPv4.Server.Pool.{i}.StaticAddress"
	err |= USP_REGISTER_Object(DHCPv4_SERVER_POOL_STATIC ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv4_SERVER_POOL_STATIC ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv4_SERVER_POOL ".{i}.StaticAddressNumberOfEntries", DHCPv4_SERVER_POOL_STATIC ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL_STATIC ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL_STATIC ".{i}.Chaddr", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL_STATIC ".{i}.Yiaddr", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	char *unique_keys_pool_static[] = { "Chaddr" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv4_SERVER_POOL_STATIC ".{i}", unique_keys_pool_static, NUM_ELEM(unique_keys_pool_static));

#define DHCPv4_SERVER_POOL_OPTION "Device.DHCPv4.Server.Pool.{i}.Option"
	err |= USP_REGISTER_Object(DHCPv4_SERVER_POOL_OPTION ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv4_SERVER_POOL_OPTION ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv4_SERVER_POOL ".{i}.OptionNumberOfEntries", DHCPv4_SERVER_POOL ".{i}.Option.{i}");
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL_OPTION ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL_OPTION ".{i}.Tag", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv4_SERVER_POOL_OPTION ".{i}.Value", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_pool_option[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv4_SERVER_POOL_OPTION ".{i}", unique_keys_pool_option, NUM_ELEM(unique_keys_pool_option));

#define DHCPv4_SERVER_POOL_CLIENT "Device.DHCPv4.Server.Pool.{i}.Client"
	err |= USP_REGISTER_Object(DHCPv4_SERVER_POOL_CLIENT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv4_SERVER_POOL_CLIENT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv4_SERVER_POOL ".{i}.ClientNumberOfEntries", DHCPv4_SERVER_POOL_CLIENT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_SERVER_POOL_CLIENT ".{i}.Chaddr", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_SERVER_POOL_CLIENT ".{i}.Active", uspd_get_value, DM_BOOL);
	char *unique_keys_pool_client[] = { "Chaddr" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv4_SERVER_POOL_CLIENT ".{i}", unique_keys_pool_client, NUM_ELEM(unique_keys_pool_client));


#define DHCPv4_SERVER_POOL_CLIENT_IPV4 DHCPv4_SERVER_POOL_CLIENT ".{i}.IPv4Address"
	err |= USP_REGISTER_Object(DHCPv4_SERVER_POOL_CLIENT_IPV4 ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(DHCPv4_SERVER_POOL_CLIENT_IPV4 ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv4_SERVER_POOL_CLIENT ".{i}.IPv4AddressNumberOfEntries", DHCPv4_SERVER_POOL_CLIENT_IPV4 ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_SERVER_POOL_CLIENT_IPV4 ".{i}.IPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_SERVER_POOL_CLIENT_IPV4 ".{i}.LeaseTimeRemaining", uspd_get_value, DM_DATETIME);
	char *unique_keys_spool_ipv4_client[] = { "IPAddress" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv4_SERVER_POOL_CLIENT_IPV4 ".{i}", unique_keys_spool_ipv4_client, NUM_ELEM(unique_keys_spool_ipv4_client));

#define DHCPv4_SERVER_POOL_CLIENT_OPTION DHCPv4_SERVER_POOL_CLIENT ".{i}.Option"
	err |= USP_REGISTER_Object(DHCPv4_SERVER_POOL_CLIENT_OPTION ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(DHCPv4_SERVER_POOL_CLIENT_OPTION ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv4_SERVER_POOL_CLIENT ".{i}.OptionNumberOfEntries", DHCPv4_SERVER_POOL_CLIENT_OPTION ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_SERVER_POOL_CLIENT_OPTION ".{i}.Tag", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv4_SERVER_POOL_CLIENT_IPV4 ".{i}.Value", uspd_get_value, DM_STRING);
	char *unique_keys_spool_client_option[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv4_SERVER_POOL_CLIENT_OPTION ".{i}", unique_keys_spool_client_option, NUM_ELEM(unique_keys_spool_client_option));


	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_DHCPv6_init(void)
{
	int err = USP_ERR_OK;
#define DHCPv6_CLIENT_ROOT "Device.DHCPv6.Client"
	err |= USP_REGISTER_Object(DHCPv6_CLIENT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv6_CLIENT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.DHCPv6.ClientNumberOfEntries", DHCPv6_CLIENT_ROOT ".{i}");
	err |= USP_REGISTER_SyncOperation(DHCPv6_CLIENT_ROOT ".{i}.Renew()", uspd_operate_sync);

	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_CLIENT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_CLIENT_ROOT ".{i}.DUID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_ROOT ".{i}.RequestAddresses", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_ROOT ".{i}.RequestPrefixes", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_ROOT ".{i}.RapidCommit", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_ROOT ".{i}.SuggestedT1", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_ROOT ".{i}.SuggestedT2", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_CLIENT_ROOT ".{i}.SupportedOptions", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_ROOT ".{i}.RequestedOptions", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_ROOT ".{i}.Renew", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

	char *unique_keys_dhcpv6_client[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_CLIENT_ROOT ".{i}", unique_keys_dhcpv6_client, NUM_ELEM(unique_keys_dhcpv6_client));

#define DHCPv6_CLIENT_SERVER_ROOT "Device.DHCPv6.Client.{i}.Server"
	err |= USP_REGISTER_Object(DHCPv6_CLIENT_SERVER_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv6_CLIENT_ROOT".{i}.ServerNumberOfEntries", DHCPv6_CLIENT_SERVER_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_CLIENT_SERVER_ROOT ".{i}.SourceAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_CLIENT_SERVER_ROOT ".{i}.DUID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_CLIENT_SERVER_ROOT ".{i}.InformationRefreshTime", uspd_get_value, DM_DATETIME);
	char *unique_keys_v6_client_server[] = { "SourceAddress" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_CLIENT_SERVER_ROOT ".{i}", unique_keys_v6_client_server, NUM_ELEM(unique_keys_v6_client_server));

#define DHCPv6_CLIENT_SENTOP_ROOT "Device.DHCPv6.Client.{i}.SentOption"
	err |= USP_REGISTER_Object(DHCPv6_CLIENT_SENTOP_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv6_CLIENT_SENTOP_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv6_CLIENT_ROOT".{i}.SentOptionNumberOfEntries", DHCPv6_CLIENT_SENTOP_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_SENTOP_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_SENTOP_ROOT ".{i}.Tag", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_CLIENT_SENTOP_ROOT ".{i}.Value", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_v6_sentop[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_CLIENT_SENTOP_ROOT ".{i}", unique_keys_v6_sentop, NUM_ELEM(unique_keys_v6_sentop));

#define DHCPv6_CLIENT_REC_ROOT "Device.DHCPv6.Client.{i}.ReceivedOption"
	err |= USP_REGISTER_Object(DHCPv6_CLIENT_REC_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(DHCPv6_CLIENT_REC_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv6_CLIENT_ROOT".{i}.ReceivedOptionNumberOfEntries", DHCPv6_CLIENT_REC_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_CLIENT_REC_ROOT ".{i}.Tag", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_CLIENT_REC_ROOT ".{i}.Value", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_CLIENT_REC_ROOT ".{i}.Server", uspd_get_value, DM_STRING);

	char *unique_keys_v6_client_rec[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_CLIENT_REC_ROOT ".{i}", unique_keys_v6_client_rec, NUM_ELEM(unique_keys_v6_client_rec));


#define DHCPv6_SERVER "Device.DHCPv6.Server"
#define DHCPv6_SERVER_POOL "Device.DHCPv6.Server.Pool"
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

	err |= USP_REGISTER_Object(DHCPv6_SERVER_POOL ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv6_SERVER_POOL ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv6_SERVER ".PoolNumberOfEntries", DHCPv6_SERVER_POOL ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.DUID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.DUIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.VendorClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.VendorClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.UserClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.UserClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.SourceAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.SourceAddressMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.SourceAddressExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.IANAEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.IANAManualPrefixes", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL ".{i}.IANAPrefixes", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.IAPDEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.IAPDManualPrefixes", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL ".{i}.IAPDPrefixes", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL ".{i}.IAPDAddLength", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_v6_server_pool[] = { "Order" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_SERVER_POOL ".{i}", unique_keys_v6_server_pool, NUM_ELEM(unique_keys_v6_server_pool));



#define DHCPv6_SERVER_POOL_CLIENT "Device.DHCPv6.Server.Pool.{i}.Client"
	err |= USP_REGISTER_Object(DHCPv6_SERVER_POOL_CLIENT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv6_SERVER_POOL_CLIENT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv6_SERVER_POOL ".{i}.ClientNumberOfEntries", DHCPv6_SERVER_POOL ".{i}.Client.{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT ".{i}.SourceAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT ".{i}.Active", uspd_get_value, DM_BOOL);
	char *unique_keys_v6_server_pool_client[] = { "SourceAddress" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_SERVER_POOL_CLIENT ".{i}", unique_keys_v6_server_pool_client, NUM_ELEM(unique_keys_v6_server_pool_client));
#define DHCPv6_SERVER_POOL_CLIENT_IPV6 DHCPv6_SERVER_POOL_CLIENT ".{i}.IPv6Address"
	err |= USP_REGISTER_Object(DHCPv6_SERVER_POOL_CLIENT_IPV6 ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(DHCPv6_SERVER_POOL_CLIENT_IPV6 ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv6_SERVER_POOL_CLIENT ".{i}.IPv6AddressNumberOfEntries", DHCPv6_SERVER_POOL_CLIENT_IPV6 ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT_IPV6 ".{i}.IPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT_IPV6 ".{i}.PreferredLifeTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT_IPV6 ".{i}.ValidLifeTime", uspd_get_value, DM_DATETIME);
	char *unique_keys_spool_ipv6_client[] = { "IPAddress" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_SERVER_POOL_CLIENT_IPV6 ".{i}", unique_keys_spool_ipv6_client, NUM_ELEM(unique_keys_spool_ipv6_client));
#define DHCPv6_SERVER_POOL_CLIENT_PREFIX DHCPv6_SERVER_POOL_CLIENT ".{i}.IPv6Prefix"
	err |= USP_REGISTER_Object(DHCPv6_SERVER_POOL_CLIENT_PREFIX ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(DHCPv6_SERVER_POOL_CLIENT_PREFIX ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv6_SERVER_POOL_CLIENT ".{i}.IPv6PrefixNumberOfEntries", DHCPv6_SERVER_POOL_CLIENT_PREFIX ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT_PREFIX ".{i}.Prefix", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT_PREFIX ".{i}.PreferredLifeTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT_PREFIX ".{i}.ValidLifeTime", uspd_get_value, DM_DATETIME);
	char *unique_keys_spool_prefix_client[] = { "Prefix" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_SERVER_POOL_CLIENT_PREFIX ".{i}", unique_keys_spool_prefix_client, NUM_ELEM(unique_keys_spool_prefix_client));


#define DHCPv6_SERVER_POOL_CLIENT_OPTION DHCPv6_SERVER_POOL_CLIENT ".{i}.Option"
	err |= USP_REGISTER_Object(DHCPv6_SERVER_POOL_CLIENT_OPTION ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(DHCPv6_SERVER_POOL_CLIENT_OPTION ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv6_SERVER_POOL_CLIENT ".{i}.OptionNumberOfEntries", DHCPv6_SERVER_POOL_CLIENT_OPTION ".{i}");

	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT_OPTION ".{i}.Tag", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DHCPv6_SERVER_POOL_CLIENT_OPTION ".{i}.Value", uspd_get_value, DM_STRING);
	char *unique_keys_spool_v6_client_option[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_SERVER_POOL_CLIENT_OPTION ".{i}", unique_keys_spool_v6_client_option, NUM_ELEM(unique_keys_spool_v6_client_option));

#define DHCPv6_SERVER_POOL_OPTION "Device.DHCPv6.Server.Pool.{i}.Option"
	err |= USP_REGISTER_Object(DHCPv6_SERVER_POOL_OPTION ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DHCPv6_SERVER_POOL_OPTION ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DHCPv6_SERVER_POOL ".{i}.OptionNumberOfEntries", DHCPv6_SERVER_POOL ".{i}.Option.{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL_OPTION ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL_OPTION ".{i}.Tag", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL_OPTION ".{i}.Value", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DHCPv6_SERVER_POOL_OPTION ".{i}.PassthroughClient", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_v6_server_pool_option[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DHCPv6_SERVER_POOL_OPTION ".{i}", unique_keys_v6_server_pool_option, NUM_ELEM(unique_keys_v6_server_pool_option));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_IEEE8021x_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_Users_init(void)
{
	int err = USP_ERR_OK;
#define USERS_USER_ROOT "Device.Users.User"
	// Register parameters implemented by this component
	err |= USP_REGISTER_Object(USERS_USER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(USERS_USER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.Users.UserNumberOfEntries", USERS_USER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(USERS_USER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERS_USER_ROOT ".{i}.RemoteAccessCapable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERS_USER_ROOT ".{i}.Username", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERS_USER_ROOT ".{i}.Password", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(USERS_USER_ROOT ".{i}.Language", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	char *unique_keys_user[] = { "Username" };
	err |= USP_REGISTER_Object_UniqueKey(USERS_USER_ROOT ".{i}", unique_keys_user, NUM_ELEM(unique_keys_user));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_SmartCardReaders_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_UPnP_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_DLNA_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_Firewall_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_FIREWALL_ROOT "Device.Firewall"
	char *unique_keys[] = { "Name" };
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_ROOT ".Config", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_ROOT ".AdvancedLevel", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_FIREWALL_ROOT ".Type", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_FIREWALL_ROOT ".Version", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_FIREWALL_ROOT ".LastChange", uspd_get_value, DM_STRING);

#define FIREWALL_LEVEL_ROOT "Device.Firewall.Level"
	err |= USP_REGISTER_Object(FIREWALL_LEVEL_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(FIREWALL_LEVEL_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_FIREWALL_ROOT ".LevelNumberOfEntries", FIREWALL_LEVEL_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_LEVEL_ROOT ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_LEVEL_ROOT ".{i}.Description", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_LEVEL_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(FIREWALL_LEVEL_ROOT ".{i}.Chain", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_LEVEL_ROOT ".{i}.PortMappingEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_LEVEL_ROOT ".{i}.DefaultPolicy", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_LEVEL_ROOT ".{i}.DefaultLogPolicy", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_Object_UniqueKey(FIREWALL_LEVEL_ROOT ".{i}", unique_keys, NUM_ELEM(unique_keys));

#define FIREWALL_CHAIN_ROOT "Device.Firewall.Chain"
	err |= USP_REGISTER_Object(FIREWALL_CHAIN_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(FIREWALL_CHAIN_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_FIREWALL_ROOT ".ChainNumberOfEntries", FIREWALL_CHAIN_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_ROOT ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(FIREWALL_CHAIN_ROOT ".{i}.Creator", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_Object_UniqueKey(FIREWALL_CHAIN_ROOT ".{i}", unique_keys, NUM_ELEM(unique_keys));

#define FIREWALL_CHAIN_RULE_ROOT "Device.Firewall.Chain.{i}.Rule"
	err |= USP_REGISTER_Object(FIREWALL_CHAIN_RULE_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(FIREWALL_CHAIN_RULE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(FIREWALL_CHAIN_ROOT ".{i}.RuleNumberOfEntries", FIREWALL_CHAIN_RULE_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(FIREWALL_CHAIN_RULE_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.Description", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.Target", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.TargetChain", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.Log", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(FIREWALL_CHAIN_RULE_ROOT ".{i}.CreationDate", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.ExpiryDate", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.SourceInterface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.SourceInterfaceExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DestInterface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DestInterfaceExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DestAllInterfaces", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.IPVersion", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DestIP", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DestMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DestIPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.SourceIP", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.SourceMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.SourceIPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.Protocol", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.ProtocolExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DestPort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DestPortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DestPortExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.SourcePort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.SourcePortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.SourcePortExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DSCP", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.DSCPExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.X_IOPSYS_EU_IcmpType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.X_IOPSYS_EU_SourceMac", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.X_IOPSYS_EU_TimeSpan.Days", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.X_IOPSYS_EU_TimeSpan.StartTime", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.X_IOPSYS_EU_TimeSpan.StopTime", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(FIREWALL_CHAIN_RULE_ROOT ".{i}.X_IOPSYS_EU_TimeSpan.SupportedDays", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_chain_rule[] = { "Alias" };
	err |= USP_REGISTER_Object_UniqueKey(FIREWALL_CHAIN_RULE_ROOT ".{i}", unique_keys_chain_rule, NUM_ELEM(unique_keys_chain_rule));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_PeriodicStatistics_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_FaultMgmt_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_Security_init(void)
{
	int err = USP_ERR_OK;
	/*
	 Device.Security.
	 Device.Security.Certificate.{i}.
	 */
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_FAP_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_BulkData_init(void)
{
	int err = USP_ERR_OK;
	// This is handled by obuspa
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_XMPP_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_XMPP_ROOT "Device.XMPP"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_XMPP_ROOT ".SupportedServerConnectAlgorithms", uspd_get_value, DM_BOOL);
#define XMPP_CONN_ROOT DEVICE_XMPP_ROOT ".Connection"
	err |= USP_REGISTER_Object(XMPP_CONN_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(XMPP_CONN_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_XMPP_ROOT ".ConnectionNumberOfEntries", XMPP_CONN_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.Username", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.Password", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.Domain", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.Resource", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(XMPP_CONN_ROOT ".{i}.JabberID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(XMPP_CONN_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(XMPP_CONN_ROOT ".{i}.LastChangeDate", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.ServerConnectAlgorithm", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.KeepAliveInterval", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.ServerConnectAttempts", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.ServerRetryInitialInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.ServerRetryIntervalMultiplier", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.ServerRetryMaxInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_ROOT ".{i}.UseTLS", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(XMPP_CONN_ROOT ".{i}.TLSEstablished", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(XMPP_CONN_ROOT ".{i}.Stats.ReceivedMessages", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(XMPP_CONN_ROOT ".{i}.Stats.TransmittedMessages", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(XMPP_CONN_ROOT ".{i}.Stats.ReceivedErrorMessages", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(XMPP_CONN_ROOT ".{i}.Stats.TransmittedErrorMessages", uspd_get_value, DM_UINT);
	char *unique_keys_xmpp_conn[] = { "Username", "Domain", "Resource"};
	err |= USP_REGISTER_Object_UniqueKey(XMPP_CONN_ROOT ".{i}", unique_keys_xmpp_conn, NUM_ELEM(unique_keys_xmpp_conn));
#define XMPP_CONN_SERVER_ROOT XMPP_CONN_ROOT ".{i}.Server"
	err |= USP_REGISTER_Object(XMPP_CONN_SERVER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(XMPP_CONN_SERVER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(XMPP_CONN_ROOT ".{i}.ServerNumberOfEntries", XMPP_CONN_SERVER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_SERVER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_SERVER_ROOT ".{i}.Priority", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_SERVER_ROOT ".{i}.Weight", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_SERVER_ROOT ".{i}.ServerAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(XMPP_CONN_SERVER_ROOT ".{i}.Port", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_xmpp_conn_serv[] = { "ServerAddress", "Port"};
	err |= USP_REGISTER_Object_UniqueKey(XMPP_CONN_SERVER_ROOT ".{i}", unique_keys_xmpp_conn_serv, NUM_ELEM(unique_keys_xmpp_conn_serv));
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_IEEE1905_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_MQTT_init(void)
{
	int err = USP_ERR_OK;
	// This is handled by obuspa
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_DynamicDNS_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_DDNS_ROOT "Device.DynamicDNS"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DDNS_ROOT ".SupportedServices", uspd_get_value, DM_STRING);

#define DDNS_CLIENT_ROOT "Device.DynamicDNS.Client"
	err |= USP_REGISTER_Object(DDNS_CLIENT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DDNS_CLIENT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DDNS_ROOT ".ClientNumberOfEntries", DDNS_CLIENT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_CLIENT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DDNS_CLIENT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DDNS_CLIENT_ROOT ".{i}.LastError", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_CLIENT_ROOT ".{i}.Server", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_CLIENT_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_CLIENT_ROOT ".{i}.Username", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_CLIENT_ROOT ".{i}.Password", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define CLIENT_HOSTNAME_ROOT "Device.DynamicDNS.Client.{i}.Hostname"
	err |= USP_REGISTER_Object(CLIENT_HOSTNAME_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	// err |= USP_REGISTER_DBParam_Alias(CLIENT_HOSTNAME_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DDNS_CLIENT_ROOT ".{i}.HostnameNumberOfEntries", CLIENT_HOSTNAME_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(CLIENT_HOSTNAME_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(CLIENT_HOSTNAME_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(CLIENT_HOSTNAME_ROOT ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(CLIENT_HOSTNAME_ROOT ".{i}.LastUpdate", uspd_get_value, DM_DATETIME);

#define DDNS_SERVER_ROOT "Device.DynamicDNS.Server"
	err |= USP_REGISTER_Object(DDNS_SERVER_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(DDNS_SERVER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DDNS_ROOT ".ServerNumberOfEntries", DDNS_SERVER_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_SERVER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_SERVER_ROOT ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_SERVER_ROOT ".{i}.ServiceName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_SERVER_ROOT ".{i}.ServerAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_SERVER_ROOT ".{i}.ServerPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DDNS_SERVER_ROOT ".{i}.SupportedProtocols", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_SERVER_ROOT ".{i}.Protocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_SERVER_ROOT ".{i}.CheckInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_SERVER_ROOT ".{i}.RetryInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DDNS_SERVER_ROOT ".{i}.MaxRetries", uspd_get_value, uspd_set_value, NULL, DM_UINT);

	char *unique_keys_ddnsclient[] = { "Server", "Username" };
	err |= USP_REGISTER_Object_UniqueKey(DDNS_CLIENT_ROOT ".{i}", unique_keys_ddnsclient, NUM_ELEM(unique_keys_ddnsclient));
	char *unique_keys_clienthostname[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(CLIENT_HOSTNAME_ROOT ".{i}", unique_keys_clienthostname, NUM_ELEM(unique_keys_clienthostname));
	char *unique_keys_ddnsserver[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DDNS_SERVER_ROOT ".{i}", unique_keys_ddnsserver, NUM_ELEM(unique_keys_ddnsserver));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_LEDs_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_LEDs_ROOT "Device.LEDs"
#define LEDs_LED_ROOT "Device.LEDs.LED"
	err |= USP_REGISTER_Object(LEDs_LED_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(LEDs_LED_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_LEDs_ROOT ".LEDNumberOfEntries", LEDs_LED_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(LEDs_LED_ROOT ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(LEDs_LED_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(LEDs_LED_ROOT ".{i}.Reason", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(LEDs_LED_ROOT ".{i}.CyclePeriodRepetitions", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(LEDs_LED_ROOT ".{i}.Location", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(LEDs_LED_ROOT ".{i}.RelativeXPosition", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(LEDs_LED_ROOT ".{i}.RelativeYPosition", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(LEDs_LED_ROOT ".{i}.CurrentCycleElement.CycleElementReference", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(LEDs_LED_ROOT ".{i}.CurrentCycleElement.Color", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(LEDs_LED_ROOT ".{i}.CurrentCycleElement.Duration", uspd_get_value, DM_UINT);

#define LED_CYCLEELEMENT_ROOT "Device.LEDs.LED.{i}.CycleElement"
	err |= USP_REGISTER_Object(LED_CYCLEELEMENT_ROOT ".{i}", NULL, uspd_add, uspd_add_notify, NULL, uspd_del, NULL);
	err |= USP_REGISTER_DBParam_Alias(LED_CYCLEELEMENT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(LEDs_LED_ROOT ".{i}.CycleElementNumberOfEntries", LED_CYCLEELEMENT_ROOT ".{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(LED_CYCLEELEMENT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(LED_CYCLEELEMENT_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(LED_CYCLEELEMENT_ROOT ".{i}.Color", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(LED_CYCLEELEMENT_ROOT ".{i}.Duration", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(LED_CYCLEELEMENT_ROOT ".{i}.FadeInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);

	char *unique_keys_led[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(LEDs_LED_ROOT ".{i}", unique_keys_led, NUM_ELEM(unique_keys_led));
	char *unique_keys_ledcelem[] = { "Order" };
	err |= USP_REGISTER_Object_UniqueKey(LED_CYCLEELEMENT_ROOT ".{i}", unique_keys_ledcelem, NUM_ELEM(unique_keys_ledcelem));

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_BASAPM_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_LMAP_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_LocalAgent_init(void)
{
	int err = USP_ERR_OK;
	// This is handled by obuspa
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_STOMP_init(void)
{
	int err = USP_ERR_OK;
	// This is handled by obuspa
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_Standby_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_SoftwareModules_init(void)
{
	int err = USP_ERR_OK;
	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;
}

int vendor_ProxiedDevice_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_PROXIEDDEVICE_ROOT "Device.ProxiedDevice"
	// Register parameters implemented by this component
	err |= USP_REGISTER_Object(DEVICE_PROXIEDDEVICE_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_PROXIEDDEVICE_ROOT ".{i}.Alias", NULL);

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
		return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;

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

int iopsys_dm_Init(void)
{
	int err = USP_ERR_OK;
	err |= vendor_device_init();
	err |= vendor_reset_init();
	err |= vendor_factory_reset_init();
	err |= vendor_Services_init();
	err |= vendor_DeviceInfo_init();
	err |= vendor_Time_init();
	err |= vendor_UserInterface_init();
	err |= vendor_InterfaceStack_init();
	err |= vendor_DSL_init();
	err |= vendor_FAST_init();
	err |= vendor_Optical_init();
	err |= vendor_Cellular_init();
	err |= vendor_ATM_init();
	err |= vendor_PTM_init();
	err |= vendor_Ethernet_init();
	err |= vendor_USB_init();
	err |= vendor_HPNA_init();
	err |= vendor_MoCA_init();
	err |= vendor_Ghn_init();
	err |= vendor_HomePlug_init();
	err |= vendor_UPA_init();
	err |= vendor_WiFi_init();
	err |= vendor_ZigBee_init();
	err |= vendor_Bridging_init();
	err |= vendor_PPP_init();
	err |= vendor_IP_init();
	err |= vendor_LLDP_init();
	err |= vendor_IPsec_init();
	err |= vendor_GRE_init();
	err |= vendor_L2TPv3_init();
	err |= vendor_VXLAN_init();
	err |= vendor_MAP_init();
	err |= vendor_CaptivePortal_init();
	err |= vendor_Routing_init();
	err |= vendor_NeighborDiscovery_init();
	err |= vendor_RouterAdvertisement_init();
	err |= vendor_IPv6rd_init();
	err |= vendor_DSLite_init();
	err |= vendor_QoS_init();
	err |= vendor_LANConfigSecurity_init();
	err |= vendor_Hosts_init();
	err |= vendor_DNS_init();
	err |= vendor_NAT_init();
	err |= vendor_PCP_init();
	err |= vendor_DHCPv4_init();
	err |= vendor_DHCPv6_init();
	err |= vendor_IEEE8021x_init();
	err |= vendor_Users_init();
	err |= vendor_SmartCardReaders_init();
	err |= vendor_UPnP_init();
	err |= vendor_DLNA_init();
	err |= vendor_Firewall_init();
	err |= vendor_PeriodicStatistics_init();
	err |= vendor_FaultMgmt_init();
	err |= vendor_Security_init();
	err |= vendor_FAP_init();
	err |= vendor_BulkData_init();
	err |= vendor_XMPP_init();
	err |= vendor_IEEE1905_init();
	err |= vendor_MQTT_init();
	err |= vendor_DynamicDNS_init();
	err |= vendor_LEDs_init();
	err |= vendor_BASAPM_init();
	err |= vendor_LMAP_init();
	err |= vendor_LocalAgent_init();
	err |= vendor_STOMP_init();
	err |= vendor_Standby_init();
	err |= vendor_SoftwareModules_init();
	err |= vendor_ProxiedDevice_init();

	err |= vendor_operate_async_init();
	// Seed data model with instance numbers from the uspd
	if (is_running_cli_local_command == false)
	{
		iopsys_dm_instance_init();
	}

	return err;
}

int uspd_get_names(char *path)
{
	uint32_t id;
	struct ubus_context *ctx = ubus_connect(NULL);
	struct blob_buf b = { };

	if (!ctx) {
		USP_LOG_Error("[%s:%d] ubus_connect failed",__func__, __LINE__);
		return USP_ERR_INTERNAL_ERROR;
	}

	if (ubus_lookup_id(ctx, USP_UBUS, &id)) {
		USP_LOG_Error("[%s:%d] %s not present",__func__, __LINE__, USP_UBUS);
		ubus_free(ctx);
		return USP_ERR_INTERNAL_ERROR;
	}

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "path", path);
	if (ubus_invoke(ctx, id, "instances", b.head, store_call_result_data,
			NULL, USPD_TIMEOUT)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, path);
		ubus_free(ctx);
		blob_buf_free(&b);
		return USP_ERR_INTERNAL_ERROR;
	}
	blob_buf_free(&b);
	ubus_free(ctx);
	return USP_ERR_OK;
}

void update_instance_vector(str_vector_t *vec, char *param)
{
        char instance[MAX_DM_PATH]={'\0'};
        char *token = strtok(param, ".");

        while(token) {
                strcat(instance, token);
                if(isdigit(token[0])){
                        STR_VECTOR_Add_IfNotExist(vec, instance);
                }
                strcat(instance, ".");
                token = strtok(NULL, ".");
        }
}

void update_path_vector(str_vector_t *vec, char *param, unsigned flags)
{
	if(flags&GET_ALL_INSTANCES) {
		update_instance_vector(vec, param);
	} else {
		size_t slen = strlen(param);
		if(param[slen-1]!='.')
			STR_VECTOR_Add_IfNotExist(vec, param);
	}
}

int json_get_params(str_vector_t *vec, unsigned flag)
{
	JsonNode *parameters;

	if((parameters = json_find_member(g_uspd_json_db, "parameters")) != NULL) {
		JsonNode *element;
		json_foreach(element, parameters) {
			JsonNode *parameter;
			if((parameter = json_find_member(element, "parameter")) != NULL) {
				if(parameter->tag == JSON_STRING) {
					update_path_vector(vec, parameter->string_, flag);
				}
			}
		}
		json_delete(parameters);
	}
	return USP_ERR_OK;
}
int uspd_get_parameter(char *path, str_vector_t *vec, unsigned flags)
{
	if(USP_ERR_OK == uspd_get_names(path)) {
		json_get_params(vec, flags);
	}
	return USP_ERR_OK;
}
// This function must be called before getting instance numbers from db
// to correctly populate the instances of vendor added datamodels
static int iopsys_dm_instance_init(void)
{
	str_vector_t instance_vector;
	STR_VECTOR_Init(&instance_vector);
	uspd_get_parameter("Device.", &instance_vector, GET_ALL_INSTANCES);
	for(size_t i=0; i< instance_vector.num_entries; ++i) {
		USP_LOG_Debug("## Instance name |%s|", instance_vector.vector[i]);
		USP_DM_InformInstance(instance_vector.vector[i]);
	}
	STR_VECTOR_Destroy(&instance_vector);
	return USP_ERR_OK;
}
