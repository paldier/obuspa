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
 * \file vendor_operate_async.c
 *
 * IOPSYS implementaion of async operate commands
 *
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
#define IP_DIAG "Device.IP.Diagnostics."
#define IPPING_DIAG "Device.IP.Diagnostics.IPPing"
#define TRACEROUTE_DIAG "Device.IP.Diagnostics.TraceRoute"
#define DOWNLOAD_DIAG "Device.IP.Diagnostics.DownloadDiagnostics"
#define UPLOAD_DIAG "Device.IP.Diagnostics.UploadDiagnostics"
#define UDPECHO_DIAG "Device.IP.Diagnostics.UDPEchoDiagnostics"
#define SERVERSELECTION_DIAG "Device.IP.Diagnostics.ServerSelectionDiagnostics"
#define NSLOOKUP_DIAG "Device.DNS.Diagnostics.NSLookupDiagnostics"

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

static char *wifi_diag_output_args[] =
{
    "Result.",
};

static char *vendor_cfg_backup_input_args[] =
{
    "URL",
    "Username",
    "Password"
};

static char *vendor_cfg_restore_input_args[] =
{
    "URL",
    "Username",
    "Password",
    "FileSize",
    "TargetFileName",
    "CheckSumAlgorithm",
    "CheckSum"
};

static char *ipping_diag_input_args[] =
{
    "Host",
    "Interface",
    "ProtocolVersion",
    "NumberOfRepetitions",
    "Timeout",
    "DataBlockSize",
    "DSCP"
};

static char *ipping_diag_output_args[] =
{
    "SuccessCount",
    "FailureCount",
    "AverageResponseTime",
    "MinimumResponseTime",
    "MaximumResponseTime",
    "AverageResponseTimeDetailed",
    "MinimumResponseTimeDetailed",
    "MaximumResponseTimeDetailed"
};

static char *traceroute_diag_input_args[] =
{
    "Host",
    "Interface",
    "ProtocolVersion",
    "NumberOfTries",
    "Timeout",
    "DataBlockSize",
    "DSCP",
    "MaxHopCount"
};

static char *traceroute_diag_output_args[] =
{
    "ResponseTime",
    "RouteHops"
};

static char *download_diag_input_args[] =
{
    "DownloadURL",
    "Interface",
    "DSCP",
    "EthernetPriority",
    "ProtocolVersion",
    "NumberOfConnections",
    "EnablePerConnectionResults"
};

static char *download_diag_output_args[] =
{
    "ROMTime",
    "BOMTime",
    "EOMTime",
    "TestBytesReceived",
    "TotalBytesReceived",
    "TotalBytesSent",
    "TestBytesReceivedUnderFullLoading",
    "TotalBytesReceivedUnderFullLoading",
    "TotalBytesSentUnderFullLoading",
    "PeriodOfFullLoading",
    "TCPOpenRequestTime",
    "TCPOpenResponseTime"
};

static char *upload_diag_input_args[] =
{
    "UploadURL",
    "TestFileLength",
    "Interface",
    "DSCP",
    "EthernetPriority",
    "ProtocolVersion",
    "NumberOfConnections",
    "EnablePerConnectionResults"
};

static char *upload_diag_output_args[] =
{
    "ROMTime",
    "BOMTime",
    "EOMTime",
    "TestBytesSent",
    "TotalBytesReceived",
    "TotalBytesSent",
    "TestBytesSentUnderFullLoading",
    "TotalBytesReceivedUnderFullLoading"
    "TotalBytesSentUnderFullLoading",
    "PeriodOfFullLoading",
    "TCPOpenRequestTime",
    "TCPOpenResponseTime"
};

static char *udp_echo_diag_input_args[] =
{
    "Host",
    "Port",
    "Interface",
    "ProtocolVersion",
    "NumberOfRepetitions",
    "Timeout",
    "DataBlockSize",
    "DSCP",
    "InterTransmissionTime"
};

static char *udp_echo_diag_output_args[] =
{
    "SuccessCount",
    "FailureCount",
    "AverageResponseTime",
    "MinimumResponseTime",
    "MaximumResponseTime"
};

static char *server_selection_diag_input_args[] =
{
    "HostList",
    "Interface",
    "ProtocolVersion",
    "NumberOfRepetitions",
    "Port",
    "Protocol",
    "Timeout"
};

static char *server_selection_diag_output_args[] =
{
    "FastestHost",
    "AverageResponseTime",
    "MinimumResponseTime",
    "MaximumResponseTime"
};

static char *nslookup_diag_input_args[] =
{
    "HostName",
    "Interface",
    "DNSServer",
    "NumberOfRepetitions",
    "Timeout"
};

static char *nslookup_diag_output_args[] =
{
    "SuccessCount",
    "NSLookupResult"
};

struct output_list_t {
    char *command;
    char **args;
    size_t argc;
};

static struct output_list_t output_list[] = {
    {WIFI_NDIAG, wifi_diag_output_args, ARRAY_SIZE(wifi_diag_output_args)},
    {IPPING_DIAG, ipping_diag_output_args, ARRAY_SIZE(ipping_diag_output_args)},
    {TRACEROUTE_DIAG, traceroute_diag_output_args, ARRAY_SIZE(traceroute_diag_output_args)},
    {DOWNLOAD_DIAG, download_diag_output_args, ARRAY_SIZE(download_diag_output_args)},
    {UPLOAD_DIAG, upload_diag_output_args, ARRAY_SIZE(upload_diag_output_args)},
    {UDPECHO_DIAG, udp_echo_diag_output_args, ARRAY_SIZE(udp_echo_diag_output_args)},
    {SERVERSELECTION_DIAG, server_selection_diag_output_args, ARRAY_SIZE(server_selection_diag_output_args)},
    {NSLOOKUP_DIAG, nslookup_diag_output_args, ARRAY_SIZE(nslookup_diag_output_args)}
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

void save_output_args(input_cond_t *cond, output_res_t *res, kv_vector_t *output_args)
{
    JsonNode *json;
    if((json = json_decode(res->result_str)) == NULL) {
        USP_LOG_Error("Decoding of json failed");
        return;
    }
    size_t alen = ARRAY_SIZE(output_list);

    for(size_t i=0; i<alen; ++i) {
        if(strstr(cond->path, output_list[i].command)) {
            size_t len = output_list[i].argc;
            for(size_t j=0; j<len; j++) {
                JsonNode *jr;
                if((jr = json_find_member(json, output_list[i].args[j]))!=NULL) {
                    char *encoded_result = json_encode(jr);
                    USP_ARG_Add(output_args, output_list[i].args[j], encoded_result);
                    json_delete(jr);
                }
            }
            break;
        }
    }
    json_delete(json);
}

void *OperationThreadMain(void *param)
{
    input_cond_t *cond = (input_cond_t *) param;
    output_res_t results;
    output_res_t *res = &results;
    char *err_msg;
    int err = USP_ERR_OK;
    kv_vector_t *output_args;

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
    USP_LOG_Info("=== Operation completed with result=%d ===", err);
    USP_LOG_Info("Result: %s", res->result_str);
    // Save all results into the output arguments using KV_VECTOR_ functions
    output_args = USP_ARG_Create();
    save_output_args(cond, res, output_args);

    // Inform the protocol handler, that the operation has completed
    // Ownership of the output args passes to protocol handler
    err_msg = (err != USP_ERR_OK) ? res->err_msg : NULL;
    USP_SIGNAL_OperationComplete(cond->request_instance, err, err_msg, output_args);

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
    err = OS_UTILS_CreateThread(OperationThreadMain, cond);
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_COMMAND_FAILURE;
    }

    // Ownership of the input conditions has passed to the thread
    return err;
}

int Wifi_NeighboringWiFiDiagnostics_Init(void)
{
    int err = USP_ERR_OK;

    // Register neighboring wifi diagnostics
    err |= USP_REGISTER_AsyncOperation("Device.WiFi.NeighboringWiFiDiagnostic()", async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.WiFi.NeighboringWiFiDiagnostic()", NULL, 0, wifi_diag_output_args, NUM_ELEM(wifi_diag_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int VendorConfig_Backup_Init(void)
{
    int err = USP_ERR_OK;

    // Register vendor config backup
    err |= USP_REGISTER_AsyncOperation("Device.DeviceInfo.VendorConfigFile.{i}.Backup()", async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DeviceInfo.VendorConfigFile.{i}.Backup()", vendor_cfg_backup_input_args, NUM_ELEM(vendor_cfg_backup_input_args), NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int VendorConfig_Restore_Init(void)
{
    int err = USP_ERR_OK;

    // Register vendor config restore
    err |= USP_REGISTER_AsyncOperation("Device.DeviceInfo.VendorConfigFile.{i}.Restore()", async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DeviceInfo.VendorConfigFile.{i}.Restore()", vendor_cfg_restore_input_args, NUM_ELEM(vendor_cfg_restore_input_args), NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int IP_Diag_IPPing_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.IP.Diagnostics.IPPing()",
                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IP.Diagnostics.IPPing()",
                       ipping_diag_input_args,
                       NUM_ELEM(ipping_diag_input_args),
                       ipping_diag_output_args,
                       NUM_ELEM(ipping_diag_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int IP_Diag_TraceRoute_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.IP.Diagnostics.TraceRoute()",
                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IP.Diagnostics.TraceRoute()",
                       traceroute_diag_input_args,
                       NUM_ELEM(traceroute_diag_input_args),
                       traceroute_diag_output_args,
                       NUM_ELEM(traceroute_diag_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int IP_Diag_DownloadDiagnostics_Init(void)
{
    int err = USP_ERR_OK;

    err |=
        USP_REGISTER_AsyncOperation("Device.IP.Diagnostics.DownloadDiagnostics()",
                       async_operate_handler, NULL);
    err |=
        USP_REGISTER_OperationArguments("Device.IP.Diagnostics.DownloadDiagnostics()",
                       download_diag_input_args,
                       NUM_ELEM(download_diag_input_args),
                       download_diag_output_args,
                       NUM_ELEM(download_diag_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int IP_Diag_UploadDiagnostics_Init(void)
{
    int err = USP_ERR_OK;

    err |=
        USP_REGISTER_AsyncOperation("Device.IP.Diagnostics.UploadDiagnostics()",
                       async_operate_handler, NULL);
    err |=
        USP_REGISTER_OperationArguments("Device.IP.Diagnostics.UploadDiagnostics()",
                       upload_diag_input_args,
                       NUM_ELEM(upload_diag_input_args),
                       upload_diag_output_args,
                       NUM_ELEM(upload_diag_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int IP_Diag_UDPEchoDiagnostics_Init(void)
{
    int err = USP_ERR_OK;

    err |=
        USP_REGISTER_AsyncOperation("Device.IP.Diagnostics.UDPEchoDiagnostics()",
                       async_operate_handler, NULL);
    err |=
        USP_REGISTER_OperationArguments("Device.IP.Diagnostics.UDPEchoDiagnostics()",
                       udp_echo_diag_input_args,
                       NUM_ELEM(udp_echo_diag_input_args),
                       udp_echo_diag_output_args,
                       NUM_ELEM(udp_echo_diag_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int IP_Diag_ServerSelectionDiagnostics_Init(void)
{
    int err = USP_ERR_OK;

    err |=
        USP_REGISTER_AsyncOperation("Device.IP.Diagnostics.ServerSelectionDiagnostics()",
                       async_operate_handler, NULL);
    err |=
        USP_REGISTER_OperationArguments("Device.IP.Diagnostics.ServerSelectionDiagnostics()",
                       server_selection_diag_input_args,
                       NUM_ELEM(server_selection_diag_input_args),
                       server_selection_diag_output_args,
                       NUM_ELEM(server_selection_diag_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int DNS_Diag_NSLookupDiagnostics_Init(void)
{
    int err = USP_ERR_OK;

    err |=
        USP_REGISTER_AsyncOperation("Device.DNS.Diagnostics.NSLookupDiagnostics()",
                       async_operate_handler, NULL);
    err |=
        USP_REGISTER_OperationArguments("Device.DNS.Diagnostics.NSLookupDiagnostics()",
                       nslookup_diag_input_args,
                       NUM_ELEM(nslookup_diag_input_args),
                       nslookup_diag_output_args,
                       NUM_ELEM(nslookup_diag_output_args));

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

    err |= Wifi_NeighboringWiFiDiagnostics_Init();
    err |= VendorConfig_Backup_Init();
    err |= VendorConfig_Restore_Init();
    err |= IP_Diag_IPPing_Init();
    err |= IP_Diag_TraceRoute_Init();
    err |= IP_Diag_DownloadDiagnostics_Init();
    err |= IP_Diag_UploadDiagnostics_Init();
    err |= IP_Diag_UDPEchoDiagnostics_Init();
    err |= IP_Diag_ServerSelectionDiagnostics_Init();
    err |= DNS_Diag_NSLookupDiagnostics_Init();
    return err;
}
