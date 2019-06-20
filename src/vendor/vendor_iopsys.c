/*
 * vendor_iopsys.c: vendor implementaion of datamodel
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
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

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

#define USP_UBUS "usp.raw"
extern bool is_running_cli_local_command;

char *dm_alias_list[] =
{
	"Device.Bridging.Bridge.*.Alias",
	"Device.Bridging.Bridge.*.Port.*.Alias",
	"Device.DHCPv4.Client.*.Alias",
	"Device.DHCPv4.Client.*.ReqOption.*.Alias",
	"Device.DHCPv4.Server.Pool.*.Alias",
	"Device.DHCPv6.Client.*.Alias",
	"Device.DHCPv6.Server.Pool.*.Alias",
	"Device.DeviceInfo.VendorConfigFile.*.Alias",
	"Device.DeviceInfo.VendorLogFile.*.Alias",
	"Device.Ethernet.Interface.*.Alias",
	"Device.Ethernet.Link.*.Alias",
	"Device.Ethernet.VLANTermination.*.Alias",
	"Device.IP.Interface.*.Alias",
	"Device.IP.Interface.*.IPv4Address.*.Alias",
	"Device.NAT.InterfaceSetting.*.Alias",
	"Device.Routing.Router.*.Alias",
	"Device.Routing.Router.*.IPv4Forwarding.*.Alias",
	"Device.Services.VoiceService.*.Alias",
	"Device.Users.User.*.Alias",
	"Device.WiFi.AccessPoint.*.Alias",
	"Device.WiFi.Radio.*.Alias",
	"Device.Firewall.Chain.*.Alias",
	"Device.Firewall.Chain.*.Rule.*.Alias",
	"Device.Firewall.Level.*.Alias",
	"Device.WiFi.SSID.*.Alias"
	//"Device.X_IOPSYS_EU_Buttons.*.Alias",
	//"Device.X_IOPSYS_EU_Dropbear.*.Alias",
	//"Device.X_IOPSYS_EU_IpAccCfg.X_IOPSYS_EU_IpAccListCfgObj.*.Alias",
	//"Device.X_IOPSYS_EU_Owsd.X_IOPSYS_EU_ListenObj.*.Alias"
};

bool uspd_set(char *path, char *value);
int iopsys_dm_instance_init(void);

static void receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
	if (!msg) {
		USP_LOG_Error("[%s:%d] recieved msg is null",__func__, __LINE__);
		return;
	}
	char *str = NULL;
	str = (char *) blobmsg_format_json_indent(msg, true, -1);
	strcpy(req->priv, str);

	if(str)
		free(str);
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
	if(json_str)
		free(json_str);
}

static void receive_data_print(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char *str;
	if (!msg)
		return;

	str = blobmsg_format_json_indent(msg, true, -1);
	USP_LOG_Info("%s", str);
	free(str);
}

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
		return USP_ERR_INTERNAL_ERROR;
	}

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "path", path);
	if (ubus_invoke(ctx, id, "get", b.head, receive_call_result_data, json_buff, 3000)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, path);
		return USP_ERR_INTERNAL_ERROR;
	}
	return USP_ERR_OK;
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

	if(USP_ERR_OK == uspd_get(req->path, json_buff))
		json_get_value_index(json_buff, NULL, buf, 0);

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
		return USP_ERR_INTERNAL_ERROR;
	}

	if (ubus_lookup_id(ctx, USP_UBUS, &id)) {
		USP_LOG_Error("[%s:%d] %s not present",__func__, __LINE__, USP_UBUS);
		return USP_ERR_INTERNAL_ERROR;
	}

	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "action", action);

	/* invoke a method on a specific object */
	if (ubus_invoke(ctx, id, "operate", b.head, receive_data_print, NULL, 2000)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, path);
		return USP_ERR_INTERNAL_ERROR;
	}
	return USP_ERR_OK;
}
int process_dm_aliases(char *path)
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
		int count=1;
		JsonNode *node;
		json_foreach(node, parameters) {
			JsonNode *parameter, *valueNode;
			char value[MAX_DM_SHORT_VALUE_LEN] = {'\0'};
			parameter = json_find_member(node, "parameter");
			valueNode = json_find_member(node, "value");
			if((parameter->tag & valueNode->tag) == JSON_STRING) {
				USP_LOG_Debug("parameter |%s|, value |%s|\n", parameter->string_, valueNode->string_);
				if(0 == strcmp(valueNode->string_, "")) {
					sprintf(value, "cpe-%d", count);
					uspd_set(parameter->string_, value);
				} else {
					strcpy(value, valueNode->string_);
				}
				err = DATA_MODEL_SetParameterInDatabase(parameter->string_, value);
				++count;
			}
			json_delete(parameter);
			json_delete(valueNode);
		}
	}
	json_delete(json);
	return(err);
}

bool uspd_set(char *path, char *value)
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
		return USP_ERR_INTERNAL_ERROR;
	}

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "path", path);
	blobmsg_add_string(&b, "value", value);
	if (ubus_invoke(ctx, id, "set", b.head, receive_call_result_status, &status, 2000)) {
		USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, path);
		return false;
	}
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
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ROOT ".InterfaceStackNumberOfEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ROOT ".ProxiedDeviceNumberOfEntries", uspd_get_value, DM_UINT);
	return err;
}

int vendor_Services_init(void)
{
	int err = USP_ERR_OK;
	//#define DEVICE_SERVICE_ROOT "Device.Services"
	//CreateNode(DEVICE_SERVICE_ROOT, kDMNodeType_Object_SingleInstance, DEVICE_SERVICE_ROOT);
	return err;
}

int vendor_DeviceInfo_init(void)
{
	int err = USP_ERR_OK;
#define DEVICE_DEVICEINFO_ROOT "Device.DeviceInfo"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".DeviceCategory", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".Manufacturer", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".ManufacturerOUI", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".CID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".PEN", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DEVICEINFO_ROOT ".FriendlyName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".ModelName", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".ModelNumber", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".Description", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".ProductClass", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".SerialNumber", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".HardwareVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".SoftwareVersion", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DEVICEINFO_ROOT ".ProvisioningCode", uspd_get_value,
			uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".UpTime", uspd_get_value, DM_INT);

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".DeviceLog", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".MemoryStatus.Free", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".MemoryStatus.Total", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".ProcessStatus.CPUUsage", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DEVICEINFO_ROOT ".SpecVersion", uspd_get_value, DM_STRING);

#define DEVICE_PROCESSSTATUS_ROOT "Device.DeviceInfo.ProcessStatus.Process"
	err |= USP_REGISTER_Param_NumEntries("Device.DeviceInfo.ProcessStatus.ProcessNumberOfEntries", DEVICE_PROCESSSTATUS_ROOT ".{i}");
	//err |= USP_REGISTER_Object(DEVICE_PROCESSSTATUS_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PROCESSSTATUS_ROOT ".{i}.CPUTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PROCESSSTATUS_ROOT ".{i}.Command", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PROCESSSTATUS_ROOT ".{i}.PID", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PROCESSSTATUS_ROOT ".{i}.Priority", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PROCESSSTATUS_ROOT ".{i}.Size", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PROCESSSTATUS_ROOT ".{i}.State", uspd_get_value, DM_STRING);
	char *unique_keys_process[] = { "PID" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_PROCESSSTATUS_ROOT ".{i}", unique_keys_process, NUM_ELEM(unique_keys_process));

#define DEVICE_VENDORCONFIG_ROOT "Device.DeviceInfo.VendorConfigFile"
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DEVICEINFO_ROOT ".VendorConfigFileNumberOfEntries",
			DEVICE_VENDORCONFIG_ROOT ".{i}");

	//err |= USP_REGISTER_Object(DEVICE_VENDORCONFIG_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_VENDORCONFIG_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_VENDORCONFIG_ROOT ".{i}.Date", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_VENDORCONFIG_ROOT ".{i}.Description", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_VENDORCONFIG_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_VENDORCONFIG_ROOT ".{i}.UseForBackupRestore", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_VENDORCONFIG_ROOT ".{i}.Version", uspd_get_value, DM_STRING);
	char *unique_keys[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_VENDORCONFIG_ROOT ".{i}", unique_keys, NUM_ELEM(unique_keys));

#define DEVICE_VENDORLOGFILE_ROOT "Device.DeviceInfo.VendorLogFile"
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DEVICEINFO_ROOT ".VendorLogFileNumberOfEntries",
			DEVICE_VENDORLOGFILE_ROOT ".{i}");
	//err |= USP_REGISTER_Object(DEVICE_VENDORLOGFILE_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_VENDORLOGFILE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_VENDORLOGFILE_ROOT ".{i}.MaximumSize", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_VENDORLOGFILE_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_VENDORLOGFILE_ROOT ".{i}.Persistent", uspd_get_value, DM_BOOL);
	char *unique_keys_log[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_VENDORLOGFILE_ROOT ".{i}", unique_keys_log, NUM_ELEM(unique_keys_log));

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
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".LocalTimeZone", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer1", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer2", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer3", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer4", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_TIME_ROOT ".NTPServer5", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_TIME_ROOT ".Status", uspd_get_value, DM_STRING);
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
#define DEVICE_USERINTERFACE_RA_ROOT "Device.UserInterface.RemoteAccess"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_RA_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_RA_ROOT ".Port", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERINTERFACE_RA_ROOT ".Protocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_USERINTERFACE_RA_ROOT ".SupportedProtocols", uspd_get_value, DM_STRING);
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
	int err = USP_ERR_OK;
	/*
	 Device.InterfaceStack.{i}.
	*/
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

#define DEVICE_ETHERNET_INTERFACE_ROOT "Device.Ethernet.Interface"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.DuplexMode", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.MaxBitRate", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.MACAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	char *unique_keys_interface[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_ETHERNET_INTERFACE_ROOT ".{i}", unique_keys_interface, NUM_ELEM(unique_keys_interface));

#define DEVICE_ETHERNET_LINK_ROOT "Device.Ethernet.Link"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_ETHERNET_LINK_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ETHERNET_LINK_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ETHERNET_LINK_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_LINK_ROOT ".{i}.MACAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_LINK_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_LINK_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	char *unique_keys_link[] = { "Name" };
	char *unique_keys_link1[] = { "MACAddress" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_ETHERNET_LINK_ROOT ".{i}", unique_keys_link, NUM_ELEM(unique_keys_link));
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_ETHERNET_LINK_ROOT ".{i}", unique_keys_link1, NUM_ELEM(unique_keys_link1));

#define DEVICE_ETHERNET_VLANT_ROOT "Device.Ethernet.VLANTermination"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_ETHERNET_VLANT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ETHERNET_VLANT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ETHERNET_VLANT_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_VLANT_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ETHERNET_VLANT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ETHERNET_VLANT_ROOT ".{i}.TPID", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ETHERNET_VLANT_ROOT ".{i}.VLANID", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	char *unique_keys_vlan[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_ETHERNET_VLANT_ROOT ".{i}", unique_keys_vlan, NUM_ELEM(unique_keys_vlan));

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
#define WIFI_ROOT "Device.WiFi"
	//err |= USP_REGISTER_SyncOperation(WIFI_ROOT ".NeighboringWiFiDiagnostic()", uspd_operate_sync);
	err |= USP_REGISTER_SyncOperation(WIFI_ROOT ".Reset()", uspd_operate_sync);
#define DEVICE_WIFI_AP_ROOT "Device.WiFi.AccessPoint"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_WIFI_AP_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.MACAddressControlEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.MaxAssociatedDevices", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.SSIDAdvertisementEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_AP_ROOT ".{i}.SSIDReference", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Security.KeyPassphrase", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Security.ModeEnabled", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Security.PreSharedKey", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Security.RadiusSecret", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Security.RadiusServerIPAddr", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Security.RadiusServerPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Security.RekeyingInterval", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Security.WEPKey", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.Security.X_IOPSYS_EU_WEPKeyIndex", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.X_IOPSYS_EU_IEEE80211r.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_AP_ROOT ".{i}.WMMEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_AP_ROOT ".{i}.Security.ModesSupported", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_SyncOperation(DEVICE_WIFI_AP_ROOT ".{i}.Security.Reset()", uspd_operate_sync);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_AP_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	char *unique_keys_ap[] = { "SSIDReference" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_WIFI_AP_ROOT ".{i}", unique_keys_ap, NUM_ELEM(unique_keys_ap));

#define DEVICE_AP_AD_ROOT DEVICE_WIFI_AP_ROOT".{i}.AssociatedDevice"
	err |= USP_REGISTER_Object(DEVICE_AP_AD_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_WIFI_AP_ROOT ".{i}.AssociatedDeviceNumberOfEntries", DEVICE_AP_AD_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Active", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.LastDataDownlinkRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.LastDataUplinkRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.MACAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.SignalStrength", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Stats.FailedRetransCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Stats.MultipleRetryCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Stats.RetransCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_AP_AD_ROOT ".{i}.Stats.RetryCount", uspd_get_value, DM_UINT);
	char *unique_keys_ad[] = { "MACAddress" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_AP_AD_ROOT ".{i}", unique_keys_ad, NUM_ELEM(unique_keys_ad));

#define DEVICE_NWIFI_ROOT "Device.WiFi.NeighboringWiFiDiagnostic"
	err |= USP_REGISTER_Object(DEVICE_NWIFI_ROOT ".Result.{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_NWIFI_ROOT ".ResultNumberOfEntries", DEVICE_NWIFI_ROOT ".Result.{i}");
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_NWIFI_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_NWIFI_ROOT ".Result.{i}.BSSID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_NWIFI_ROOT ".Result.{i}.Channel", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_NWIFI_ROOT ".Result.{i}.Noise", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_NWIFI_ROOT ".Result.{i}.OperatingFrequencyBand", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_NWIFI_ROOT ".Result.{i}.SSID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_NWIFI_ROOT ".Result.{i}.SignalStrength", uspd_get_value, DM_INT);

#define DEVICE_WIFI_RADIO_ROOT "Device.WiFi.Radio"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_WIFI_RADIO_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.ChannelsInUse", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.MaxBitRate", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.OperatingFrequencyBand", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.PossibleChannels", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.SupportedFrequencyBands", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_RADIO_ROOT ".{i}.SupportedStandards", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_RADIO_ROOT ".{i}.AutoChannelEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_RADIO_ROOT ".{i}.Channel", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_RADIO_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_RADIO_ROOT ".{i}.OperatingChannelBandwidth", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_RADIO_ROOT ".{i}.OperatingStandards", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_RADIO_ROOT ".{i}.X_IOPSYS_EU_DFSEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_RADIO_ROOT ".{i}.X_IOPSYS_EU_MaxAssociations", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_radio[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_WIFI_RADIO_ROOT ".{i}", unique_keys_radio, NUM_ELEM(unique_keys_radio));

#define DEVICE_WIFI_SSID_ROOT "Device.WiFi.SSID"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_WIFI_SSID_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_SSID_ROOT ".{i}.BSSID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_SSID_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_SSID_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_SSID_ROOT ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_WIFI_SSID_ROOT ".{i}.SSID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_SSID_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_SSID_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_SSID_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_SSID_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_SSID_ROOT ".{i}.status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite("Device.WiFi.X_IOPSYS_EU_Bandsteering_Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	char *unique_keys_ssid[] = { "Name" };
	char *unique_keys_ssid1[] = { "BSSID" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_WIFI_SSID_ROOT ".{i}", unique_keys_ssid, NUM_ELEM(unique_keys_ssid));
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_WIFI_SSID_ROOT ".{i}", unique_keys_ssid1, NUM_ELEM(unique_keys_ssid1));

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

#define DEVICE_BRIDGING_ROOT "Device.Bridging.Bridge"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_BRIDGING_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_BRIDGING_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.ManagementPort", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.Stats.BytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.Stats.BytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.Stats.PacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.Stats.PacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_BRIDGING_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_BRIDGING_ROOT ".{i}.X_IOPSYS_EU_AssociatedInterfaces", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	char *unique_keys_bridge[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_BRIDGING_ROOT ".{i}.Port.{i}", unique_keys_bridge, NUM_ELEM(unique_keys_bridge));
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
#define DEVICE_PPP_INT "Device.PPP.Interface"
	/*
	char *unique_keys_interface[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_PPP_INT ".{i}", unique_keys_interface, NUM_ELEM(unique_keys_interface));
	*/
	err |= USP_REGISTER_SyncOperation(DEVICE_PPP_INT ".{i}.Reset()", uspd_operate_sync);
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

#define DEVICE_IP_DDIAG_ROOT "Device.IP.Diagnostics.DownloadDiagnostics"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".BOMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DDIAG_ROOT ".DSCP", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DDIAG_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".DownloadDiagnosticMaxConnections", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".DownloadTransports", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DDIAG_ROOT ".DownloadURL", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".EOMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DDIAG_ROOT ".EnablePerConnectionResults", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DDIAG_ROOT ".EthernetPriority", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DDIAG_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DDIAG_ROOT ".NumberOfConnections", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_Param_NumEntries("Device.IP.Diagnostics.DownloadDiagnostics.PerConnectionResultNumberOfEntries", DEVICE_IP_DDIAG_ROOT ".PerConnectionResult.{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".PeriodOfFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DDIAG_ROOT ".ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".ROMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".TCPOpenRequestTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".TCPOpenResponseTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".TestBytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".TestBytesReceivedUnderFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".TotalBytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".TotalBytesReceivedUnderFullLoading", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".TotalBytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DDIAG_ROOT ".TotalBytesSentUnderFullLoading", uspd_get_value, DM_UINT);

#define DEVICE_IP_IPPING_ROOT "Device.IP.Diagnostics.IPPing"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_IPPING_ROOT ".AverageResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_IPPING_ROOT ".AverageResponseTimeDetailed", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_IPPING_ROOT ".DSCP", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_IPPING_ROOT ".DataBlockSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_IPPING_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_IPPING_ROOT ".FailureCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_IPPING_ROOT ".Host", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_IPPING_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_IPPING_ROOT ".MaximumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_IPPING_ROOT ".MaximumResponseTimeDetailed", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_IPPING_ROOT ".MinimumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_IPPING_ROOT ".MinimumResponseTimeDetailed", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_IPPING_ROOT ".NumberOfRepetitions", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_IPPING_ROOT ".ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_IPPING_ROOT ".SuccessCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_IPPING_ROOT ".Timeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);

#define DEVICE_IP_DIAG_ROOT "Device.IP.Diagnostics"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv4DownloadDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv4PingSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv4ServerSelectionDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv4TraceRouteSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv4UDPEchoDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv4UploadDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv6DownloadDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv6PingSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv6ServerSelectionDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv6TraceRouteSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv6UDPEchoDiagnosticsSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".IPv6UploadDiagnosticsSupported", uspd_get_value, DM_BOOL);

	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.AverageResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.FastestHost", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.HostList", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.MaximumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.MinimumResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.NumberOfRepetitions", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.Port", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.Protocol", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_ROOT ".ServerSelectionDiagnostics.Timeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);

#define DEVICE_IP_TDIAG_ROOT "Device.IP.Diagnostics.TraceRoute"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".DSCP", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".DataBlockSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".Host", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".MaxHopCount", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".NumberOfTries", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".ProtocolVersion", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_TDIAG_ROOT ".ResponseTime", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_TDIAG_ROOT ".RouteHopsNumberOfEntries", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_TDIAG_ROOT ".Timeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);

#define DEVICE_IP_DIAG_UCONFIG_ROOT "Device.IP.Diagnostics.UDPEchoConfig"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".BytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".BytesResponded", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".EchoPlusEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".EchoPlusSupported", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".PacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".PacketsResponded", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".SourceIPAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".TimeFirstPacketReceived", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UCONFIG_ROOT ".TimeLastPacketReceived", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UCONFIG_ROOT ".UDPPort", uspd_get_value, uspd_set_value, NULL, DM_UINT);

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

#define DEVICE_IP_DIAG_UDIAG_ROOT "Device.IP.Diagnostics.UploadDiagnostics"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".BOMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".DSCP", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".EOMTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".EnablePerConnectionResults", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".EthernetPriority", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".NumberOfConnections", uspd_get_value, uspd_set_value, NULL, DM_UINT);

	err |= USP_REGISTER_Param_NumEntries(DEVICE_IP_DIAG_UDIAG_ROOT ".PerConnectionResultNumberOfEntries", DEVICE_IP_DIAG_UDIAG_ROOT ".PerConnectionResult.{i}");

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
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_DIAG_UDIAG_ROOT ".UploadTransports", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_DIAG_UDIAG_ROOT ".UploadURL", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define DEVICE_IP_ROOT "Device.IP"
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_ROOT ".IPv4Capable", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_ROOT ".IPv4Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_ROOT ".IPv4Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_ROOT ".IPv6Capable", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_ROOT ".IPv6Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_ROOT ".IPv6Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_ROOT ".ULAPrefix", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define DEVICE_IP_INT_ROOT "Device.IP.Interface"
	err |= USP_REGISTER_Param_NumEntries("Device.IP.InterfaceNumberOfEntries", DEVICE_IP_INT_ROOT ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_IP_INT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_SyncOperation(DEVICE_IP_INT_ROOT ".{i}.Reset()", uspd_operate_sync);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.LastChange", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.Loopback", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.LowerLayers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.MaxMTUSize", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Name", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.Router", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.BytesReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.BytesSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.DiscardPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.DiscardPacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.ErrorsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.ErrorsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.MulticastPacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.PacketsReceived", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Stats.PacketsSent", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);

	char *unique_keys_interface[] = { "Name" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_IP_INT_ROOT ".{i}", unique_keys_interface, NUM_ELEM(unique_keys_interface));

	err |= USP_REGISTER_Param_NumEntries("Device.IP.Interface.{i}.TWAMPReflectorNumberOfEntries", DEVICE_IP_INT_ROOT ".{i}.TWAMPReflector.{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_ROOT ".{i}.Type", uspd_get_value, DM_STRING);

	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.IPv4Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_ROOT ".{i}.IPv6Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

#define DEVICE_IP_INT_IPv4_ROOT "Device.IP.Interface.{i}.IPv4Address"
	err |= USP_REGISTER_Param_NumEntries("Device.IP.Interface.{i}.IPv4AddressNumberOfEntries", DEVICE_IP_INT_IPv4_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_IPv4_ROOT ".{i}.AddressingType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_IP_INT_IPv4_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_IPv4_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_IPv4_ROOT ".{i}.IPAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_IP_INT_IPv4_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_IPv4_ROOT ".{i}.SubnetMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_IP_INT_IPv4_ROOT ".{i}.X_IOPSYS_EU_FirewallEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	char *unique_keys_ipv4[] = { "IPAddress", "SubnetMask" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_IP_INT_IPv4_ROOT ".{i}", unique_keys_ipv4, NUM_ELEM(unique_keys_ipv4));

#define DEVICE_IP_INT_IPv6_ROOT "Device.IP.Interface.{i}.IPv6Address"
	err |= USP_REGISTER_Param_NumEntries("Device.IP.Interface.{i}.IPv6AddressNumberOfEntries", DEVICE_IP_INT_IPv6_ROOT ".{i}");
	err |= USP_REGISTER_Param_NumEntries("Device.IP.Interface.{i}.IPv6PrefixNumberOfEntries", DEVICE_IP_INT_ROOT ".{i}.IPv6Prefix.{i}");
	/*
	char *unique_keys_ipv6[] = { "IPAddress" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_IP_INT_IPv6_ROOT ".{i}", unique_keys_ipv6, NUM_ELEM(unique_keys_ipv6));
	*/

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
	err |= USP_REGISTER_VendorParam_ReadOnly("Device.Routing.RouteInformation.Enable", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_Param_NumEntries("Device.Routing.RouteInformation.InterfaceSettingNumberOfEntries", "Device.Routing.RouteInformation.InterfaceSetting.{i}");

#define DEVICE_ROUTING_ROUTER_ROOT "Device.Routing.Router"
	err |= USP_REGISTER_Param_NumEntries("Device.Routing.RouterNumberOfEntries", DEVICE_ROUTING_ROUTER_ROOT ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_ROUTING_ROUTER_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_ROUTING_ROUTER_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ROUTING_ROUTER_ROOT ".{i}.Status", uspd_get_value, DM_STRING);

#define DEVICE_RR_IPv4FORW_ROOT "Device.Routing.Router.{i}.IPv4Forwarding"
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ROUTING_ROUTER_ROOT".{i}.IPv4ForwardingNumberOfEntries", DEVICE_RR_IPv4FORW_ROOT ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_RR_IPv4FORW_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.DestIPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.DestSubnetMask", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.Enable", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.ForwardingMetric", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.ForwardingPolicy", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.GatewayIPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.Interface", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.Origin", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.StaticRoute", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv4FORW_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	char *unique_keys_forw[] = { "DestIPAddress", "DestSubnetMask", "ForwardingPolicy", "GatewayIPAddress", "Interface", "ForwardingMetric" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_RR_IPv4FORW_ROOT ".{i}", unique_keys_forw, NUM_ELEM(unique_keys_forw));

#define DEVICE_RR_IPv6FORW_ROOT "Device.Routing.Router.{i}.IPv6Forwarding"
	err |= USP_REGISTER_Param_NumEntries(DEVICE_ROUTING_ROUTER_ROOT".{i}.IPv6ForwardingNumberOfEntries", DEVICE_RR_IPv6FORW_ROOT ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_RR_IPv6FORW_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv6FORW_ROOT ".{i}.DestIPPrefix", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv6FORW_ROOT ".{i}.Enable", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv6FORW_ROOT ".{i}.ExpirationTime", uspd_get_value, DM_DATETIME);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv6FORW_ROOT ".{i}.ForwardingMetric", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv6FORW_ROOT ".{i}.ForwardingPolicy", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv6FORW_ROOT ".{i}.Interface", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv6FORW_ROOT ".{i}.NextHop", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv6FORW_ROOT ".{i}.Origin", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_RR_IPv6FORW_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	char *unique_keys_forw6[] = { "DestIPPrefix", "ForwardingPolicy", "NextHop", "Interface", "ForwardingMetric" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_RR_IPv6FORW_ROOT ".{i}", unique_keys_forw6, NUM_ELEM(unique_keys_forw6));
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
#define DEVICE_HHOSTS_ROOT "Device.Hosts.Host"
	err |= USP_REGISTER_Param_NumEntries("Device.Hosts.HostNumberOfEntries", DEVICE_HHOSTS_ROOT ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_HHOSTS_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.Active", uspd_get_value, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.AddressSource", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.AssociatedDevice", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.DHCPClient", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.HostName", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.IPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.Layer3Interface", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.LeaseTimeRemaining", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.PhysAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.X_IOPSYS_EU_InterfaceType", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.X_IOPSYS_EU_LinkType", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_HHOSTS_ROOT ".{i}.X_IOPSYS_EU_ifname", uspd_get_value, DM_STRING);
	char *unique_keys[] = { "PhysAddress" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_HHOSTS_ROOT ".{i}", unique_keys, NUM_ELEM(unique_keys));
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
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_ROOT ".Client.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DNS_ROOT ".Client.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DNS_ROOT ".SupportedRecordTypes", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_Param_NumEntries("Device.DNS.Client.ServerNumberOfEntries", "Device.DNS.Client.Server.{i}");

#define DEVICE_DNS_DIAGn_ROOT "Device.DNS.Diagnostics.NSLookupDiagnostics"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".DNSServer", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".DiagnosticsState", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".HostName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".NumberOfRepetitions", uspd_get_value, uspd_set_value, NULL, DM_UINT);

	err |= USP_REGISTER_Param_NumEntries(DEVICE_DNS_DIAGn_ROOT".ResultNumberOfEntries", DEVICE_DNS_DIAGn_ROOT".Result.{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DNS_DIAGn_ROOT ".SuccessCount", uspd_get_value, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_DIAGn_ROOT ".Timeout", uspd_get_value, uspd_set_value, NULL, DM_UINT);

#define DEVICE_DNS_RELAY_ROOT "Device.DNS.Relay"
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DNS_RELAY_ROOT ".Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DNS_RELAY_ROOT ".Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DNS_RELAY_ROOT ".ForwardNumberOfEntries", DEVICE_DNS_RELAY_ROOT".Forwarding.{i}");
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
#define DEVICE_NAT_INT_ROOT "Device.NAT.InterfaceSetting"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_NAT_INT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_NAT_INT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_NAT_INT_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
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

#define DEVICE_DHCPv4_CLIENT_ROOT "Device.DHCPv4.Client"
	err |= USP_REGISTER_SyncOperation(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.Reset()", uspd_operate_sync);
	err |= USP_REGISTER_Param_NumEntries("Device.DHCPv4.ClientNumberOfEntries", DEVICE_DHCPv4_CLIENT_ROOT ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.DHCPServer", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.DHCPStatus", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.DNSServers", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.IPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.IPRouters", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.LeaseTimeRemaining", uspd_get_value, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.PassthroughDHCPPool", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.PassthroughEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.Renew", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.SubnetMask", uspd_get_value, DM_STRING);
	char *unique_keys[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_DHCPv4_CLIENT_ROOT ".{i}", unique_keys, NUM_ELEM(unique_keys));

#define DEVICE_DHCPv4_CLIENT_REQ_ROOT "Device.DHCPv4.Client.{i}.ReqOption"
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv4_CLIENT_ROOT".{i}.ReqOptionNumberOfEntries", DEVICE_DHCPv4_CLIENT_REQ_ROOT ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_DHCPv4_CLIENT_REQ_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_CLIENT_REQ_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_CLIENT_REQ_ROOT ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_CLIENT_REQ_ROOT ".{i}.Tag", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_CLIENT_REQ_ROOT ".{i}.Value", uspd_get_value, DM_UINT);

	char *unique_keys_req[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_DHCPv4_CLIENT_REQ_ROOT ".{i}", unique_keys_req, NUM_ELEM(unique_keys_req));
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv4_CLIENT_ROOT".{i}.SentOptionNumberOfEntries", DEVICE_DHCPv4_CLIENT_ROOT ".{i}.SentOption.{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite("Device.DHCPv4.Relay.Enable", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly("Device.DHCPv4.Relay.Status", uspd_get_value, DM_STRING);
	/*
	char *unique_keys_sent[] = { "Tag" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_DHCPv4_CLIENT_ROOT ".{i}.SentOption.{i}", unique_keys_sent, NUM_ELEM(unique_keys_sent));
	*/

	err |= USP_REGISTER_Param_NumEntries("Device.DHCPv4.Relay.ForwardingNumberOfEntries", "Device.DHCPv4.Relay.Forwarding.{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite("Device.DHCPv4.Server.Enable", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define DEVICE_DHCPv4_SPOOL "Device.DHCPv4.Server.Pool"
	err |= USP_REGISTER_Param_NumEntries("Device.DHCPv4.Server.PoolNumberOfEntries", DEVICE_DHCPv4_SPOOL ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_DHCPv4_SPOOL ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.DNSServers", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.DomainName", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.IPRouters", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.LeaseTime", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.MaxAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.MinAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_SPOOL ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.SubnetMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.X_IOPSYS_EU_DHCPServerConfigurable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv4_SPOOL ".{i}.ReservedAddresses", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv4_SPOOL ".{i}.OptionNumberOfEntries", DEVICE_DHCPv4_SPOOL ".{i}.Option.{i}");

	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv4_SPOOL ".{i}.StaticAddressNumberOfEntries", DEVICE_DHCPv4_SPOOL ".{i}.StaticAddress.{i}");

#define DEVICE_DHCPv4_SPOOL_CLIENT "Device.DHCPv4.Server.Pool.{i}.Client"
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv4_SPOOL ".{i}.ClientNumberOfEntries", DEVICE_DHCPv4_SPOOL_CLIENT ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_DHCPv4_SPOOL_CLIENT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_SPOOL_CLIENT ".{i}.Active", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_SPOOL_CLIENT ".{i}.Chaddr", uspd_get_value, DM_STRING);
	char *unique_keys_client[] = { "Chaddr" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_DHCPv4_SPOOL_CLIENT ".{i}", unique_keys_client, NUM_ELEM(unique_keys_client));
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_SPOOL_CLIENT ".{i}.IPv4Address.{i}.IPAddress", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv4_SPOOL_CLIENT ".{i}.IPv4Address.{i}.LeaseTimeRemaining", uspd_get_value, DM_DATETIME);
	char *unique_keys_ipv4_client[] = { "IPAddress" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_DHCPv4_SPOOL_CLIENT ".{i}.IPv4Address.{i}", unique_keys_ipv4_client, NUM_ELEM(unique_keys_ipv4_client));


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
#define DEVICE_DHCPv6_CLIENT_ROOT "Device.DHCPv6.Client"
	err |= USP_REGISTER_SyncOperation(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.Reset()", uspd_operate_sync);
	err |= USP_REGISTER_Param_NumEntries("Device.DHCPv6.ClientNumberOfEntries", DEVICE_DHCPv6_CLIENT_ROOT ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.DDID", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.RapidCommit", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.Renew", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.RequestAddresses", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.RequestPrefixes", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.RequestedOptions", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.SuggestedT1", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.SuggestedT2", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv6_CLIENT_ROOT ".{i}.SupportedOptions", uspd_get_value, DM_STRING);
	char *unique_keys_client[] = { "Interface" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_DHCPv6_CLIENT_ROOT ".{i}", unique_keys_client, NUM_ELEM(unique_keys_client));

	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv6_CLIENT_ROOT".{i}.ReceivedOptionNumberOfEntries", DEVICE_DHCPv6_CLIENT_ROOT ".{i}.ReceivedOption.{i}");
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv6_CLIENT_ROOT".{i}.SentOptionNumberOfEntries", DEVICE_DHCPv6_CLIENT_ROOT ".{i}.SentOption.{i}");
	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv6_CLIENT_ROOT".{i}.ServerNumberOfEntries", DEVICE_DHCPv6_CLIENT_ROOT ".{i}.Server.{i}");


#define DEVICE_DHCPv6_SPOOL "Device.DHCPv6.Server.Pool"
	err |= USP_REGISTER_VendorParam_ReadWrite("Device.DHCPv6.Server.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

	err |= USP_REGISTER_Param_NumEntries("Device.DHCPv6.Server.PoolNumberOfEntries", DEVICE_DHCPv6_SPOOL ".{i}");
	err |= USP_REGISTER_DBParam_Alias(DEVICE_DHCPv6_SPOOL ".{i}.Alias", NULL);

	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv6_SPOOL ".{i}.ClientNumberOfEntries", DEVICE_DHCPv6_SPOOL ".{i}.Client.{i}");
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.DUID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.DUIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.IANAEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.IANAManualPrefixes", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv6_SPOOL ".{i}.IANAPrefixes", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.IAPDAddLength", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.IAPDEnable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.IAPDManualPrefixes", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv6_SPOOL ".{i}.IAPDPrefixes", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.Interface", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	err |= USP_REGISTER_Param_NumEntries(DEVICE_DHCPv6_SPOOL ".{i}.OptionNumberOfEntries", DEVICE_DHCPv6_SPOOL ".{i}.Option.{i}");

	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.SourceAddress", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.SourceAddressExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.SourceAddressMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_DHCPv6_SPOOL ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.UserClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.UserClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.VendorClassID", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_DHCPv6_SPOOL ".{i}.VendorClassIDExclude", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	char *unique_keys_server[] = { "Order" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_DHCPv6_SPOOL ".{i}", unique_keys_server, NUM_ELEM(unique_keys_server));

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
#define DEVICE_USERS_ROOT "Device.Users.User"
	// Register parameters implemented by this component
	err |= USP_REGISTER_Object(DEVICE_USERS_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_USERS_ROOT ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.Users.UserNumberOfEntries", DEVICE_USERS_ROOT ".{i}");
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERS_ROOT ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERS_ROOT ".{i}.Language", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERS_ROOT ".{i}.Password", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERS_ROOT ".{i}.RemoteAccessCapable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_USERS_ROOT ".{i}.Username", uspd_get_value, uspd_set_value, NULL, DM_STRING);

	char *unique_keys[] = { "Username" };
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_USERS_ROOT ".{i}", unique_keys, NUM_ELEM(unique_keys));

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
	char *unique_keys[] = { "Name" };
	err |= USP_REGISTER_VendorParam_ReadWrite("Device.Firewall.AdvancedLevel", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite("Device.Firewall.Config", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite("Device.Firewall.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);

#define DEVICE_FIREWALL_CHAIN "Device.Firewall.Chain"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_FIREWALL_CHAIN ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries("Device.Firewall.ChainNumberOfEntries", DEVICE_FIREWALL_CHAIN ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_FIREWALL_CHAIN ".{i}.Creator", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CHAIN ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CHAIN ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_FIREWALL_CHAIN ".{i}", unique_keys, NUM_ELEM(unique_keys));

#define DEVICE_FIREWALL_CRULE "Device.Firewall.Chain.{i}.Rule"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_FIREWALL_CRULE ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries(DEVICE_FIREWALL_CHAIN ".{i}.RuleNumberOfEntries", DEVICE_FIREWALL_CRULE ".{i}");
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.Description", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.DestInterface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.DestIp", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.DestMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.DestPort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.DestPortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.Enable", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.IPVersion", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.Order", uspd_get_value, uspd_set_value, NULL, DM_UINT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.Protocol", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.SourceInterface", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.SourceIp", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.SourceMask", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.SourcePort", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.SourcePortRangeMax", uspd_get_value, uspd_set_value, NULL, DM_INT);
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_FIREWALL_CRULE ".{i}.Status", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.Target", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.TargetChain", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.X_IOPSYS_EU_IcmpType", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.X_IOPSYS_EU_SourceMac", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.X_IOPSYS_EU_TimeSpan.Days", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.X_IOPSYS_EU_TimeSpan.StartTime", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.X_IOPSYS_EU_TimeSpan.StopTime", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_CRULE ".{i}.X_IOPSYS_EU_TimeSpan.SupportedDays", uspd_get_value, uspd_set_value, NULL, DM_STRING);

#define DEVICE_FIREWALL_LEVEL "Device.Firewall.Level"
	err |= USP_REGISTER_DBParam_Alias(DEVICE_FIREWALL_LEVEL ".{i}.Alias", NULL);
	err |= USP_REGISTER_Param_NumEntries( "Device.Firewall.LevelNumberOfEntries", DEVICE_FIREWALL_LEVEL ".{i}");
	err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_FIREWALL_LEVEL ".{i}.Chain", uspd_get_value, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_LEVEL ".{i}.DefaultLogPolicy", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_LEVEL ".{i}.Description", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_LEVEL ".{i}.Name", uspd_get_value, uspd_set_value, NULL, DM_STRING);
	err |= USP_REGISTER_VendorParam_ReadWrite(DEVICE_FIREWALL_LEVEL ".{i}.PortMappingEnabled", uspd_get_value, uspd_set_value, NULL, DM_BOOL);
	err |= USP_REGISTER_Object_UniqueKey(DEVICE_FIREWALL_LEVEL ".{i}", unique_keys, NUM_ELEM(unique_keys));

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
	//err |= USP_REGISTER_Object(DEVICE_PROXIEDDEVICE_ROOT ".{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	err |= USP_REGISTER_DBParam_Alias(DEVICE_PROXIEDDEVICE_ROOT ".{i}.Alias", NULL);

	// Exit if any errors occurred
	if (err != USP_ERR_OK)
	{
	  return USP_ERR_INTERNAL_ERROR;
	}

	// If the code gets here, then registration was successful
	return USP_ERR_OK;

}

int iopsys_dm_Init(void)
{
	int err = USP_ERR_OK;
	err |= vendor_device_init();
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

	// Seed data model with instance numbers from the uspd
	if (is_running_cli_local_command == false)
	{
		iopsys_dm_instance_init();
	}

	return err;
}

// This function must be called before getting instance numbers from db
// to correctly populate the instances of vendor added datamodels
int iopsys_dm_instance_init(void)
{
	int max_dm = NUM_ELEM(dm_alias_list);

	for(int i=0; i<max_dm; ++i)
	{
		process_dm_aliases(dm_alias_list[i]);
	}

	return USP_ERR_OK;
}
