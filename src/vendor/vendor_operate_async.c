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

#define ASYNC_USPD_TIMEOUT 30000

void save_output_args(char *res, kv_vector_t *output_args);

typedef struct
{
    int request_instance;   // Instance number of this operation in the Device.LocalAgent.Request table
    char path[MAX_DM_PATH];
    kv_vector_t *input_args;
} input_cond_t;

static char *packetcapture_diag_input_args[] =
{
    "Interface",
    "Format",
    "Duration",
    "PacketCount",
    "ByteCount",
    "FileTarget",
    "FilterExpression",
    "Username",
    "Password"
};

static char *packetcapture_diag_output_args[] =
{
    "Status",
    "PacketCaptureResult.{i}.FileLocation",
    "PacketCaptureResult.{i}.StartTime",
    "PacketCaptureResult.{i}.EndTime",
    "PacketCaptureResult.{i}.Count"
};

static char *wifi_diag_output_args[] =
{
    "Result.{i}.Radio",
    "Result.{i}.SSID",
    "Result.{i}.BSSID",
    "Result.{i}.Mode",
    "Result.{i}.Channel",
    "Result.{i}.SignalStrength",
    "Result.{i}.SecurityModeEnabled",
    "Result.{i}.EncryptionMode",
    "Result.{i}.OperatingFrequencyBand",
    "Result.{i}.SupportedStandards",
    "Result.{i}.OperatingStandards",
    "Result.{i}.OperatingChannelBandwidth",
    "Result.{i}.BeaconPeriod",
    "Result.{i}.Noise",
    "Result.{i}.BasicDataTransferRates",
    "Result.{i}.SupportedDataTransferRates",
    "Result.{i}.DTIMPeriod"
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

static char *vendor_logfile_upload_input_args[] =
{
    "URL",
    "Username",
    "Password"
};

static char *device_firmwareimage_download_input_args[] =
{
    "URL",
    "AutoActivate",
    "Username",
    "Password",
    "FileSize",
    "CheckSumAlgorithm",
    "CheckSum"
};

static char *device_firmwareimage_activate_input_args[] =
{
    "Start",
    "End",
    "Mode",
    "UserMessage",
    "MaxRetries"
};

static char *dsl_ethernet_adslline_input_args[] =
{
    "Interface"
};

static char *dsl_ethernet_adslline_output_args[] =
{
    "Status",
    "ACTPSDds",
    "ACTPSDus",
    "ACTATPds",
    "ACTATPus",
    "HLINSCds",
    "HLINSCus",
    "HLINGds",
    "HLINGus",
    "HLOGGds",
    "HLOGGus",
    "HLOGpsds",
    "HLOGpsus",
    "HLOGMTds",
    "HLOGMTus",
    "LATNpbds",
    "LATNpbus",
    "SATNds",
    "SATNus",
    "HLINpsds",
    "HLINpsus",
    "QLNGds",
    "QLNGus",
    "QLNpsds",
    "QLNpsus",
    "QLNMTds",
    "QLNMTus",
    "SNRGds",
    "SNRGus",
    "SNRpsds",
    "SNRpsus",
    "SNRMTds",
    "SNRMTus",
    "BITSpsds",
    "BITSpsus"
};

static char *dsl_ethernet_seltuer_input_args[] =
{
    "Interface",
    "UERMaxMeasurementDuration"
};

static char *dsl_ethernet_seltuer_output_args[] =
{
    "Status",
    "ExtendedBandwidthOperation",
    "UER",
    "UERScaleFactor",
    "UERGroupSize",
    "UERVar"
};

static char *dsl_ethernet_seltqln_input_args[] =
{
    "Interface",
    "QLNMaxMeasurementDuration"
};

static char *dsl_ethernet_seltqln_output_args[] =
{
    "Status",
    "ExtendedBandwidthOperation",
    "QLN",
    "QLNGroupSize"
};

static char *dsl_ethernet_seltp_input_args[] =
{
    "Interface",
    "CapacityEstimateEnabling",
    "CapacitySignalPSD",
    "CapacityNoisePSD",
    "CapacityTargetMargin"
};

static char *dsl_ethernet_seltp_output_args[] =
{
    "Status",
    "LoopTermination",
    "LoopLength",
    "LoopTopology",
    "AttenuationCharacteristics",
    "MissingFilter",
    "CapacityEstimate"
};

static char *atm_diag_f5loopback_input_args[] =
{
    "Interface",
    "NumberOfRepetitions",
    "Timeout"
};

static char *atm_diag_f5loopback_output_args[] =
{
    "Status",
    "SuccessCount",
    "FailureCount",
    "AverageResponseTime",
    "MinimumResponseTime",
    "MaximumResponseTime"
};

static char *eth_wol_sendmagicpacket_input_args[] =
{
    "MACAddress",
    "Password"
};

static char *hpna_diag_phythroughput_input_args[] =
{
    "Interface",
    "NumPacketsInBurst",
    "BurstInterval",
    "TestPacketPayloadLength",
    "PayloadEncoding",
    "PayloadDataGen",
    "PayloadType",
    "PriorityLevel"
};

static char *hpna_diag_phythroughput_output_args[] =
{
    "Status",
    "Result.{i}.SrcMACAddress",
    "Result.{i}.DestMACAddress",
    "Result.{i}.PHYRate",
    "Result.{i}.BaudRate",
    "Result.{i}.SNR",
    "Result.{i}.PacketsReceived",
    "Result.{i}.Attenuation"
};

static char *hpna_diag_perfmonitor_input_args[] =
{
    "Interface",
    "SampleInterval"
};

static char *hpna_diag_perfmonitor_output_args[] =
{
    "Status",
    "Nodes.CurrentStart",
    "Nodes.CurrentEnd",
    "Nodes.NodeNumberOfEntries",
    "Nodes.Node.{i}.MACAddress",
    "Nodes.Node.{i}.BytesSent",
    "Nodes.Node.{i}.BytesReceived",
    "Nodes.Node.{i}.PacketsSent",
    "Nodes.Node.{i}.PacketsReceived",
    "Nodes.Node.{i}.BroadcastPacketsSent",
    "Nodes.Node.{i}.BroadcastPacketsReceived",
    "Nodes.Node.{i}.MulticastPacketsSent",
    "Nodes.Node.{i}.MulticastPacketsReceived",
    "Nodes.Node.{i}.PacketsCrcErrored",
    "Nodes.Node.{i}.PacketsCrcErroredHost",
    "Nodes.Node.{i}.PacketsShortErrored",
    "Nodes.Node.{i}.PacketsShortErroredHost",
    "Nodes.Node.{i}.RxPacketsDropped",
    "Nodes.Node.{i}.TxPacketsDropped",
    "Nodes.Node.{i}.ControlRequestLocal",
    "Nodes.Node.{i}.ControlReplyLocal",
    "Nodes.Node.{i}.ControlRequestRemote",
    "Nodes.Node.{i}.ControlReplyRemote",
    "Nodes.Node.{i}.PacketsSentWire",
    "Nodes.Node.{i}.BroadcastPacketsSentWire",
    "Nodes.Node.{i}.MulticastPacketsSentWire",
    "Nodes.Node.{i}.PacketsInternalControl",
    "Nodes.Node.{i}.BroadcastPacketsInternalControl",
    "Nodes.Node.{i}.PacketsReceivedQueued",
    "Nodes.Node.{i}.PacketsReceivedForwardUnknown",
    "Nodes.Node.{i}.NodeUtilization",
    "Channels.TimeStamp",
    "Channels.ChannelNumberOfEntries",
    "Channels.Channel.{i}.HostSrcMACAddress",
    "Channels.Channel.{i}.HostDestMACAddress",
    "Channels.Channel.{i}.HPNASrcMACAddress",
    "Channels.Channel.{i}.HPNADestMACAddress",
    "Channels.Channel.{i}.PHYRate",
    "Channels.Channel.{i}.BaudRate",
    "Channels.Channel.{i}.SNR",
    "Channels.Channel.{i}.PacketsSent",
    "Channels.Channel.{i}.PacketsReceived",
    "Channels.Channel.{i}.LARQPacketsReceived",
    "Channels.Channel.{i}.FlowSpec"
};

static char *ghn_diag_phythroughput_input_args[] =
{
    "Interface",
    "DiagnoseMACAddress"
};

static char *ghn_diag_phythroughput_output_args[] =
{
    "Status",
    "Result.{i}.DestinationMACAddress",
    "Result.{i}.LinkState",
    "Result.{i}.TxPhyRate",
    "Result.{i}.RxPhyRate"
};

static char *ghn_diag_perfmonitor_input_args[] =
{
    "Interface",
    "DiagnoseMACAddress",
    "SampleInterval",
    "SNRGroupLength"
};

static char *ghn_diag_perfmonitor_output_args[] =
{
    "Status",
    "Nodes.CurrentStart",
    "Nodes.CurrentEnd",
    "Nodes.NodeNumberOfEntries",
    "Nodes.Node.{i}.DestinationMACAddress",
    "Nodes.Node.{i}.BytesSent",
    "Nodes.Node.{i}.BytesReceived",
    "Nodes.Node.{i}.PacketsSent",
    "Nodes.Node.{i}.PacketsReceived",
    "Nodes.Node.{i}.ErrorsSent",
    "Nodes.Node.{i}.ErrorsReceived",
    "Nodes.Node.{i}.UnicastPacketsSent",
    "Nodes.Node.{i}.UnicastPacketsReceived",
    "Nodes.Node.{i}.DiscardPacketsSent",
    "Nodes.Node.{i}.DiscardPacketsReceived",
    "Nodes.Node.{i}.MulticastPacketsSent",
    "Nodes.Node.{i}.MulticastPacketsReceived",
    "Nodes.Node.{i}.BroadcastPacketsSent",
    "Nodes.Node.{i}.BroadcastPacketsReceived",
    "Nodes.Node.{i}.UnknownProtoPacketsReceived",
    "Nodes.Node.{i}.MgmtBytesSent",
    "Nodes.Node.{i}.MgmtBytesReceived",
    "Nodes.Node.{i}.MgmtPacketsSent",
    "Nodes.Node.{i}.MgmtPacketsReceived",
    "Nodes.Node.{i}.BlocksSent",
    "Nodes.Node.{i}.BlocksReceived",
    "Nodes.Node.{i}.BlocksResent",
    "Nodes.Node.{i}.BlocksErrorsReceived",
    "Channels.TimeStamp",
    "Channels.ChannelNumberOfEntries",
    "Channels.Channel.{i}.DestinationMACAddress",
    "Channels.Channel.{i}.SNR"
};

static char *upa_diag_interfacemeasure_input_args[] =
{
    "Type",
    "Interface",
    "Port"
};

static char *upa_diag_interfacemeasure_output_args[] =
{
    "Status",
    "Measurements",
    "RxGain"
};

static char *ipping_diag_input_args[] =
{
    "Interface",
    "ProtocolVersion",
    "Host",
    "NumberOfRepetitions",
    "Timeout",
    "DataBlockSize",
    "DSCP"
};

static char *ipping_diag_output_args[] =
{
    "Status",
    "IPAddressUsed",
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
    "Interface",
    "ProtocolVersion",
    "Host",
    "NumberOfTries",
    "Timeout",
    "DataBlockSize",
    "DSCP",
    "MaxHopCount"
};

static char *traceroute_diag_output_args[] =
{
    "Status",
    "IPAddressUsed",
    "ResponseTime",
    "RouteHops.{i}.Host",
    "RouteHops.{i}.HostAddress",
    "RouteHops.{i}.ErrorCode",
    "RouteHops.{i}.RTTimes"
};

static char *download_diag_input_args[] =
{
    "Interface",
    "DownloadURL",
    "DSCP",
    "EthernetPriority",
    "TimeBasedTestDuration",
    "TimeBasedTestMeasurementInterval",
    "TimeBasedTestMeasurementOffset",
    "ProtocolVersion",
    "NumberOfConnections",
    "EnablePerConnectionResults"
};

static char *download_diag_output_args[] =
{
    "Status",
    "IPAddressUsed",
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
    "TCPOpenResponseTime",
    "PerConnectionResult.{i}.ROMTime",
    "PerConnectionResult.{i}.BOMTime",
    "PerConnectionResult.{i}.EOMTime",
    "PerConnectionResult.{i}.TestBytesReceived",
    "PerConnectionResult.{i}.TotalBytesReceived",
    "PerConnectionResult.{i}.TotalBytesSent",
    "PerConnectionResult.{i}.TCPOpenRequestTime",
    "PerConnectionResult.{i}.TCPOpenResponseTime",
    "IncrementalResult.{i}.TestBytesReceived",
    "IncrementalResult.{i}.TotalBytesReceived",
    "IncrementalResult.{i}.TotalBytesSent",
    "IncrementalResult.{i}.StartTime",
    "IncrementalResult.{i}.EndTime"
};

static char *upload_diag_input_args[] =
{
    "Interface",
    "UploadURL",
    "DSCP",
    "EthernetPriority",
    "TestFileLength",
    "TimeBasedTestDuration",
    "TimeBasedTestMeasurementInterval",
    "TimeBasedTestMeasurementOffset",
    "ProtocolVersion",
    "NumberOfConnections",
    "EnablePerConnectionResults"
};

static char *upload_diag_output_args[] =
{
    "Status",
    "IPAddressUsed",
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
    "TCPOpenResponseTime",
    "PerConnectionResult.{i}.ROMTime",
    "PerConnectionResult.{i}.BOMTime",
    "PerConnectionResult.{i}.EOMTime",
    "PerConnectionResult.{i}.TestBytesSent",
    "PerConnectionResult.{i}.TotalBytesReceived",
    "PerConnectionResult.{i}.TotalBytesSent",
    "PerConnectionResult.{i}.TCPOpenRequestTime",
    "PerConnectionResult.{i}.TCPOpenResponseTime",
    "IncrementalResult.{i}.TestBytesSent",
    "IncrementalResult.{i}.TotalBytesReceived",
    "IncrementalResult.{i}.TotalBytesSent",
    "IncrementalResult.{i}.StartTime",
    "IncrementalResult.{i}.EndTime"
};

static char *udp_echo_diag_input_args[] =
{
    "Interface",
    "Host",
    "Port",
    "NumberOfRepetitions",
    "Timeout",
    "DataBlockSize",
    "DSCP",
    "InterTransmissionTime",
    "ProtocolVersion",
    "EnableIndividualPacketResults"
};

static char *udp_echo_diag_output_args[] =
{
    "Status",
    "IPAddressUsed",
    "SuccessCount",
    "FailureCount",
    "AverageResponseTime",
    "MinimumResponseTime",
    "MaximumResponseTime",
    "IndividualPacketResult.{i}.PacketSuccess",
    "IndividualPacketResult.{i}.PacketSendTime",
    "IndividualPacketResult.{i}.PacketReceiveTime",
    "IndividualPacketResult.{i}.TestGenSN",
    "IndividualPacketResult.{i}.TestRespSN",
    "IndividualPacketResult.{i}.TestRespRcvTimeStamp",
    "IndividualPacketResult.{i}.TestRespReplyTimeStamp",
    "IndividualPacketResult.{i}.TestRespReplyFailureCount"
};

static char *server_selection_diag_input_args[] =
{
    "Interface",
    "ProtocolVersion",
    "Protocol",
    "HostList",
    "NumberOfRepetitions",
    "Timeout"
};

static char *server_selection_diag_output_args[] =
{
    "Status",
    "FastestHost",
    "MinimumResponseTime",
    "AverageResponseTime",
    "MaximumResponseTime",
    "IPAddressUsed"
};

static char *nslookup_diag_input_args[] =
{
    "Interface",
    "HostName",
    "DNSServer",
    "Timeout",
    "NumberOfRepetitions"
};

static char *nslookup_diag_output_args[] =
{
    "Status",
    "SuccessCount",
    "Result.{i}.Status",
    "Result.{i}.AnswerType",
    "Result.{i}.HostNameReturned",
    "Result.{i}.IPAddresses",
    "Result.{i}.DNSServerIP",
    "Result.{i}.ResponseTime"
};

static char *softwaremodule_installdu_input_args[] =
{
    "URL",
    "UUID",
    "Username",
    "Password",
    "ExecutionEnvRef"
};

static char *softwaremodule_deployunit_update_input_args[]=
{
    "URL",
    "Username",
    "Password"
};

static void receive_print(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *str;
    if (!msg)
        return;

    str = blobmsg_format_json_indent(msg, true, -1);
    USP_LOG_Debug("Output data:|%s|", str);
    save_output_args(str, req->priv);
    free(str);
}

int ExecuteTestDiagnostic(char *cpath, kv_vector_t *input_args, kv_vector_t *output_args)
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
    blobmsg_add_string(&b, "proto", USP_PROTO);
    if(input_args->num_entries) {
        void *table = blobmsg_open_table(&b, "input");
        for(int i=0; i<input_args->num_entries; ++i) {
            kv = &input_args->vector[i];
            USP_LOG_Info("[%s:%d] INPUT key |%s| value|%s|",__func__, __LINE__, kv->key, kv->value);
            blobmsg_add_string(&b, kv->key, kv->value);
        }
        blobmsg_close_table(&b, table);
    }
    if (ubus_invoke(ctx, id, "operate", b.head, receive_print, output_args, ASYNC_USPD_TIMEOUT)) {
        USP_LOG_Error("[%s:%d] ubus call failed for |%s|",__func__, __LINE__, path);
        return USP_ERR_INTERNAL_ERROR;
    }

    ubus_free(ctx);
    return USP_ERR_OK;
}

void save_output_args(char *res, kv_vector_t *output_args)
{
    JsonNode *json;
    if(res == NULL) {
        USP_LOG_Error("Json data string with NULL value");
        return;
    }
    if((json = json_decode(res)) == NULL) {
        USP_LOG_Error("Decoding of json failed");
        return;
    }

    JsonNode *js_tmp;
    json_foreach(js_tmp, json) {
        char buf[64] = {0};
        memset(buf, 0, sizeof(buf));
        if(js_tmp->tag == JSON_ARRAY){
            JsonNode *inner_json;
            int inst_count = 0;
            json_foreach(inner_json, js_tmp) {
                inst_count++;
                JsonNode *inner_json2;
                json_foreach(inner_json2, inner_json) {
                    sprintf(buf, "%s.%d.%s", js_tmp->key, inst_count, inner_json2->key);
                    USP_LOG_Debug("|%s:%s|", buf, json_encode(inner_json2));
                    USP_ARG_Add(output_args, buf, json_encode(inner_json2));
                    memset(buf, 0, sizeof(buf));
                }
            }
        } else if(js_tmp->tag == JSON_OBJECT) {
            JsonNode *jnode;
            json_foreach(jnode, js_tmp) {
                if(jnode->tag == JSON_ARRAY) {
                    JsonNode *inner_json;
                    int inst_count = 0;
                    json_foreach(inner_json, jnode) {
                        inst_count++;
                        JsonNode *inner_json2;
                        json_foreach(inner_json2, inner_json) {
                            sprintf(buf, "%s.%s.%d.%s", js_tmp->key, jnode->key, inst_count, inner_json2->key);
                            USP_LOG_Debug("|%s:%s|", buf, json_encode(inner_json2));
                            USP_ARG_Add(output_args, buf, json_encode(inner_json2));
                            memset(buf, 0, sizeof(buf));
                        }
                    }

                } else {
                    sprintf(buf, "%s.%s", js_tmp->key, jnode->key);
                    USP_LOG_Debug("|%s:%s|", buf, json_encode(jnode));
                    USP_ARG_Add(output_args, buf, json_encode(jnode));
                    memset(buf, 0, sizeof(buf));
                }
            }
        } else {
            USP_LOG_Debug("|%s:%s|", js_tmp->key, json_encode(js_tmp));
            USP_ARG_Add(output_args, js_tmp->key, json_encode(js_tmp));
        }
    }
    json_delete(json);
}

void *OperationThreadMain(void *param)
{
    input_cond_t *cond = (input_cond_t *) param;
    char err_log[128];
    char *err_msg;
    int err = USP_ERR_OK;
    kv_vector_t *output_args;

    memset(err_log, 0, sizeof(err_log));

    // Exit if unable to signal that this operation is active
    err = USP_SIGNAL_OperationStatus(cond->request_instance, "Active");
    output_args = USP_ARG_Create();
    if (err == USP_ERR_OK)
    {
        // Perform the self test diagnostic
        err = ExecuteTestDiagnostic(cond->path, cond->input_args, output_args);
    }
    else
    {
        USP_SNPRINTF(err_log, sizeof(err_log), "%s: USP_SIGNAL_OperationStatus() failed", __FUNCTION__);
    }

    // Inform the protocol handler, that the operation has completed
    // Ownership of the output args passes to protocol handler
    err_msg = (err != USP_ERR_OK) ? err_log : NULL;
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

int Device_PacketCaptureDiagnostics_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.PacketCaptureDiagnostics()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.PacketCaptureDiagnostics()",	
                                           packetcapture_diag_input_args, NUM_ELEM(packetcapture_diag_input_args),
                                           packetcapture_diag_output_args, NUM_ELEM(packetcapture_diag_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
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

int VendorLogFile_Upload_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DeviceInfo.VendorLogFile.{i}.Upload()", 
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DeviceInfo.VendorLogFile.{i}.Upload()", 
                                           vendor_logfile_upload_input_args,
                                           NUM_ELEM(vendor_logfile_upload_input_args),
                                           NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_FirmwareImage_Download_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DeviceInfo.FirmwareImage.{i}.Download()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DeviceInfo.FirmwareImage.{i}.Download()",
                                           device_firmwareimage_download_input_args, 
                                           NUM_ELEM(device_firmwareimage_download_input_args),
                                           NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_FirmwareImage_Activate_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DeviceInfo.FirmwareImage.{i}.Activate()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DeviceInfo.FirmwareImage.{i}.Activate()",
                                           device_firmwareimage_activate_input_args,
                                           NUM_ELEM(device_firmwareimage_activate_input_args),
                                           NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int DSL_Ethernet_ADSLLineTest_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DSL.BondingGroup.{i}.Ethernet.Stats.ADSLLineTest()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DSL.BondingGroup.{i}.Ethernet.Stats.ADSLLineTest()",
                                           dsl_ethernet_adslline_input_args,
                                           NUM_ELEM(dsl_ethernet_adslline_input_args),
                                           dsl_ethernet_adslline_output_args,
                                           NUM_ELEM(dsl_ethernet_adslline_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int DSL_Ethernet_SELTUER_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DSL.BondingGroup.{i}.Ethernet.Stats.SELTUER()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DSL.BondingGroup.{i}.Ethernet.Stats.SELTUER()",
                                           dsl_ethernet_seltuer_input_args,
                                           NUM_ELEM(dsl_ethernet_seltuer_input_args),
                                           dsl_ethernet_seltuer_output_args,
                                           NUM_ELEM(dsl_ethernet_seltuer_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int DSL_Ethernet_SELTQLN_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DSL.BondingGroup.{i}.Ethernet.Stats.SELTQLN()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DSL.BondingGroup.{i}.Ethernet.Stats.SELTQLN()",
                                           dsl_ethernet_seltqln_input_args,
                                           NUM_ELEM(dsl_ethernet_seltqln_input_args),
                                           dsl_ethernet_seltqln_output_args,
                                           NUM_ELEM(dsl_ethernet_seltqln_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int DSL_Ethernet_SELTP_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DSL.BondingGroup.{i}.Ethernet.Stats.SELTP()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DSL.BondingGroup.{i}.Ethernet.Stats.SELTP()",
                                           dsl_ethernet_seltp_input_args,
                                           NUM_ELEM(dsl_ethernet_seltp_input_args),
                                           dsl_ethernet_seltp_output_args,
                                           NUM_ELEM(dsl_ethernet_seltp_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int ATM_Diagnostics_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.ATM.Diagnostics.F5Loopback()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.ATM.Diagnostics.F5Loopback()",
                                           atm_diag_f5loopback_input_args,
                                           NUM_ELEM(atm_diag_f5loopback_input_args),
                                           atm_diag_f5loopback_output_args,
                                           NUM_ELEM(atm_diag_f5loopback_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Ethernet_WoL_SendMagicPacket_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.Ethernet.WoL.SendMagicPacket()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.Ethernet.WoL.SendMagicPacket()",
                                           eth_wol_sendmagicpacket_input_args,
                                           NUM_ELEM(eth_wol_sendmagicpacket_input_args),
                                           NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int HPNA_Diag_PHYThroughput_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.HPNA.Diagnostics.PHYThroughput()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.HPNA.Diagnostics.PHYThroughput()",
                                           hpna_diag_phythroughput_input_args,
                                           NUM_ELEM(hpna_diag_phythroughput_input_args),
                                           hpna_diag_phythroughput_output_args,
                                           NUM_ELEM(hpna_diag_phythroughput_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int HPNA_Diag_PerformanceMonitor_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.HPNA.Diagnostics.PerformanceMonitoring()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.HPNA.Diagnostics.PerformanceMonitoring()",
                                           hpna_diag_perfmonitor_input_args,
                                           NUM_ELEM(hpna_diag_perfmonitor_input_args),
                                           hpna_diag_perfmonitor_output_args,
                                           NUM_ELEM(hpna_diag_perfmonitor_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Ghn_Diag_PHYThroughput_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.Ghn.Diagnostics.PHYThroughput()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.Ghn.Diagnostics.PHYThroughput()",
                                           ghn_diag_phythroughput_input_args,
                                           NUM_ELEM(ghn_diag_phythroughput_input_args),
                                           ghn_diag_phythroughput_output_args,
                                           NUM_ELEM(ghn_diag_phythroughput_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Ghn_Diag_PerformanceMonitor_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.Ghn.Diagnostics.PerformanceMonitoring()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.Ghn.Diagnostics.PerformanceMonitoring()",
                                           ghn_diag_perfmonitor_input_args,
                                           NUM_ELEM(ghn_diag_perfmonitor_input_args),
                                           ghn_diag_perfmonitor_output_args,
                                           NUM_ELEM(ghn_diag_perfmonitor_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int UPA_Diag_InterfaceMeasurement_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.UPA.Diagnostics.InterfaceMeasurement()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.UPA.Diagnostics.InterfaceMeasurement()",
                                           upa_diag_interfacemeasure_input_args,
                                           NUM_ELEM(upa_diag_interfacemeasure_input_args),
                                           upa_diag_interfacemeasure_output_args,
                                           NUM_ELEM(upa_diag_interfacemeasure_output_args));

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

int Device_SoftwareModule_InstallDU_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.SoftwareModules.InstallDu()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.SoftwareModules.InstallDu()",
                                           softwaremodule_installdu_input_args,
                                           NUM_ELEM(softwaremodule_installdu_input_args),
                                           NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_SoftwareModule_DeployUnit_Update_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.SoftwareModules.DeploymentUnit.{i}.Update()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.SoftwareModules.DeploymentUnit.{i}.Update()",
                                           softwaremodule_deployunit_update_input_args,
                                           NUM_ELEM(softwaremodule_deployunit_update_input_args),
                                           NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int IoTCapability_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.IoTCapability.{i}.BinaryControl.Toggle()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.BinaryControl.Toggle()",
                                           NULL, 0, NULL, 0);


    err |= USP_REGISTER_AsyncOperation("Device.IoTCapability.{i}.LevelControl.StepUp()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.LevelControl.StepUp()",
                                           NULL, 0, NULL, 0);

    err |= USP_REGISTER_AsyncOperation("Device.IoTCapability.{i}.LevelControl.StepDown()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.LevelControl.StepDown()",
                                           NULL, 0, NULL, 0);

    err |= USP_REGISTER_AsyncOperation("Device.IoTCapability.{i}.EnumControl.StepUp()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.EnumControl.StepUp()",
                                           NULL, 0, NULL, 0);

    err |= USP_REGISTER_AsyncOperation("Device.IoTCapability.{i}.EnumControl.StepDown()",
                                       async_operate_handler, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.EnumControl.StepDown()",
                                           NULL, 0, NULL, 0);

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

    err |= Device_PacketCaptureDiagnostics_Init();
    err |= Wifi_NeighboringWiFiDiagnostics_Init();
    err |= VendorConfig_Backup_Init();
    err |= VendorConfig_Restore_Init();
    err |= VendorLogFile_Upload_Init();
    err |= Device_FirmwareImage_Download_Init();
    err |= Device_FirmwareImage_Activate_Init();
    err |= DSL_Ethernet_ADSLLineTest_Init();
    err |= DSL_Ethernet_SELTUER_Init();
    err |= DSL_Ethernet_SELTQLN_Init();
    err |= DSL_Ethernet_SELTP_Init();
    err |= ATM_Diagnostics_Init();
    err |= Ethernet_WoL_SendMagicPacket_Init();
    err |= HPNA_Diag_PHYThroughput_Init();
    err |= HPNA_Diag_PerformanceMonitor_Init();
    err |= Ghn_Diag_PHYThroughput_Init();
    err |= Ghn_Diag_PerformanceMonitor_Init();
    err |= UPA_Diag_InterfaceMeasurement_Init();
    err |= IP_Diag_IPPing_Init();
    err |= IP_Diag_TraceRoute_Init();
    err |= IP_Diag_DownloadDiagnostics_Init();
    err |= IP_Diag_UploadDiagnostics_Init();
    err |= IP_Diag_UDPEchoDiagnostics_Init();
    err |= IP_Diag_ServerSelectionDiagnostics_Init();
    err |= DNS_Diag_NSLookupDiagnostics_Init();
    err |= Device_SoftwareModule_InstallDU_Init();
    err |= Device_SoftwareModule_DeployUnit_Update_Init();
    err |= IoTCapability_Init();
    return err;
}
