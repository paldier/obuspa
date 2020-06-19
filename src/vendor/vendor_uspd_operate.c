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

#include <stdio.h>

#include "common_defs.h"
#include "dm_access.h"
#include "vendor_uspd.h"


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
    "Status",
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


static char *dsl_adslline_input_args[] =
{
    "Interface"
};

static char *dsl_adslline_output_args[] =
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

static char *dsl_seltuer_input_args[] =
{
    "Interface",
    "UERMaxMeasurementDuration"
};

static char *dsl_seltuer_output_args[] =
{
    "Status",
    "ExtendedBandwidthOperation",
    "UER",
    "UERScaleFactor",
    "UERGroupSize",
    "UERVar"
};

static char *dsl_seltqln_input_args[] =
{
    "Interface",
    "QLNMaxMeasurementDuration"
};

static char *dsl_seltqln_output_args[] =
{
    "Status",
    "ExtendedBandwidthOperation",
    "QLN",
    "QLNGroupSize"
};

static char *dsl_seltp_input_args[] =
{
    "Interface",
    "CapacityEstimateEnabling",
    "CapacitySignalPSD",
    "CapacityNoisePSD",
    "CapacityTargetMargin"
};

static char *dsl_seltp_output_args[] =
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
    "TotalBytesReceivedUnderFullLoading",
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

static char *softwaremodule_deployunit_update_input_args[] =
{
    "URL",
    "Username",
    "Password"
};

static char *localagent_addcerts_input_args[] =
{
    "Alias",
    "Certificate"
};

static char *localagent_schtimer_input_args[] =
{
    "DelaySeconds"
};

static char *localagent_controller_addcerts_input_args[] =
{
    "Alias",
    "Certificate"
};

static char *localagent_cert_getfingerprint_input_args[] =
{
    "FingerprintAlgorithm"
};

static char *localagent_cert_getfingerprint_output_args[] =
{
    "Fingerprint"
};

static char *localagent_reqchallenge_input_args[] =
{
    "ChallengeRef",
    "RequestExpiration"
};

static char *localagent_reqchallenge_output_args[] =
{
    "Instruction",
    "InstructionType",
    "ValueType",
    "ChallengeID"
};

static char *localagent_challengeresp_input_args[] =
{
    "ChallengeID",
    "Value"
};

static char *swmodules_setrunlevel_input_args[] =
{
    "RequestedRunLevel"
};

static char *swmodules_setreqstate_input_args[] =
{
    "RequestedState"
};

int Device_PacketCaptureDiagnostics_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.PacketCaptureDiagnostics()",
                                       uspd_operate_async, NULL);
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
    err |= USP_REGISTER_AsyncOperation("Device.WiFi.NeighboringWiFiDiagnostic()", uspd_operate_async, NULL);
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
    err |= USP_REGISTER_AsyncOperation("Device.DeviceInfo.VendorConfigFile.{i}.Backup()", uspd_operate_async, NULL);
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
    err |= USP_REGISTER_AsyncOperation("Device.DeviceInfo.VendorConfigFile.{i}.Restore()", uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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


int Device_DSL_ADSLLinetest_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DSL.Diagnostics.ADSLLineTest()",
                                       uspd_operate_async, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DSL.Diagnostics.ADSLLineTest()",
                                           dsl_adslline_input_args,
                                           NUM_ELEM(dsl_adslline_input_args),
                                           dsl_adslline_output_args,
                                           NUM_ELEM(dsl_adslline_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_DSL_SELTUER_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DSL.Diagnostics.SELTUER()",
                                       uspd_operate_async, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DSL.Diagnostics.SELTUER()",
                                           dsl_seltuer_input_args,
                                           NUM_ELEM(dsl_seltuer_input_args),
                                           dsl_seltuer_output_args,
                                           NUM_ELEM(dsl_seltuer_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_DSL_SELTQLN_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DSL.Diagnostics.SELTQLN()",
                                       uspd_operate_async, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DSL.Diagnostics.SELTQLN()",
                                           dsl_seltqln_input_args,
                                           NUM_ELEM(dsl_seltqln_input_args),
                                           dsl_seltqln_output_args,
                                           NUM_ELEM(dsl_seltqln_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_DSL_SELTP_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.DSL.Diagnostics.SELTP()",
                                       uspd_operate_async, NULL);
    err |= USP_REGISTER_OperationArguments("Device.DSL.Diagnostics.SELTP()",
                                           dsl_seltp_input_args,
                                           NUM_ELEM(dsl_seltp_input_args),
                                           dsl_seltp_output_args,
                                           NUM_ELEM(dsl_seltp_output_args));

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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                    uspd_operate_async, NULL);
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
                                    uspd_operate_async, NULL);
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
                                    uspd_operate_async, NULL);
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
                                    uspd_operate_async, NULL);
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
                                    uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
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
                                       uspd_operate_async, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.BinaryControl.Toggle()",
                                           NULL, 0, NULL, 0);


    err |= USP_REGISTER_AsyncOperation("Device.IoTCapability.{i}.LevelControl.StepUp()",
                                       uspd_operate_async, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.LevelControl.StepUp()",
                                           NULL, 0, NULL, 0);

    err |= USP_REGISTER_AsyncOperation("Device.IoTCapability.{i}.LevelControl.StepDown()",
                                       uspd_operate_async, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.LevelControl.StepDown()",
                                           NULL, 0, NULL, 0);

    err |= USP_REGISTER_AsyncOperation("Device.IoTCapability.{i}.EnumControl.StepUp()",
                                       uspd_operate_async, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.EnumControl.StepUp()",
                                           NULL, 0, NULL, 0);

    err |= USP_REGISTER_AsyncOperation("Device.IoTCapability.{i}.EnumControl.StepDown()",
                                       uspd_operate_async, NULL);
    err |= USP_REGISTER_OperationArguments("Device.IoTCapability.{i}.EnumControl.StepDown()",
                                           NULL, 0, NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int MTP_WebSocket_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.LocalAgent.Controller.{i}.MTP.{i}.WebSocket.Reset()",
                                       uspd_operate_async, NULL);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int E2ESession_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.LocalAgent.Controller.{i}.E2ESession.Reset()",
                                      uspd_operate_async, NULL);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int SWModules_DeployUnit_Uninstall_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.SoftwareModules.DeploymentUnit.{i}.Uninstall()",
                                      uspd_operate_async, NULL);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_TempSensor_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.DeviceInfo.TemperatureStatus.TemperatureSensor.{i}.Reset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_UserInterface_PasswdReset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.UserInterface.PasswordReset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_USBHost_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.USB.USBHosts.Host.{i}.Reset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_WiFi_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.WiFi.Reset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_AP_Security_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.WiFi.AccessPoint.{i}.Security.Reset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_PPP_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.PPP.Interface.{i}.Reset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_IPInterface_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.IP.Interface.{i}.Reset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_DHCPv4_Renew_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.DHCPv4.Client.{i}.Renew()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_DHCPv6_Renew_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.DHCPv6.Client.{i}.Renew()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_IEEE8021x_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.IEEE8021x.Supplicant.{i}.Reset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_IEEE8021x_Disconnect_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.IEEE8021x.Supplicant.{i}.Disconnect()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_SmartCardReader_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.SmartCardReaders.SmartCardReader.{i}.Reset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_SampleSet_ForceSample_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.PeriodicStatistics.SampleSet.{i}.ForceSample()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_FAP_GPSReset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.FAP.GPS.GPSReset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_LocalAgent_AddCerts_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.LocalAgent.AddCertificate()",
                                      uspd_operate_sync);
    err |= USP_REGISTER_OperationArguments("Device.LocalAgent.AddCertificate()",
					   localagent_addcerts_input_args,
					   NUM_ELEM(localagent_addcerts_input_args),
					   NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_Controller_SchTimer_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.LocalAgent.Controller.{i}.ScheduleTimer()",
                                      uspd_operate_sync);
    err |= USP_REGISTER_OperationArguments("Device.LocalAgent.Controller.{i}.ScheduleTimer()",
                                        localagent_schtimer_input_args,
                                        NUM_ELEM(localagent_schtimer_input_args),
                                        NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_Controller_AddCerts_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.LocalAgent.Controller.{i}.AddMyCertificate()",
                                      uspd_operate_sync);
    err |= USP_REGISTER_OperationArguments("Device.LocalAgent.Controller.{i}.AddMyCertificate()",
                                        localagent_controller_addcerts_input_args,
                                        NUM_ELEM(localagent_controller_addcerts_input_args),
                                        NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_Controller_SendOnBoardReq_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.LocalAgent.Controller.{i}.SendOnBoardRequest()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_LocalAgent_ReqCancel_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.LocalAgent.Request.{i}.Cancel()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_LocalAgent_CertsDelete_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.LocalAgent.Certificate.{i}.Delete()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_LocalAgent_GetFingerPrint_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.LocalAgent.Certificate.{i}.GetFingerprint()",
                                      uspd_operate_sync);
    err |= USP_REGISTER_OperationArguments("Device.LocalAgent.Certificate.{i}.GetFingerprint()",
                                        localagent_cert_getfingerprint_input_args,
                                        NUM_ELEM(localagent_cert_getfingerprint_input_args),
                                        localagent_cert_getfingerprint_output_args,
                                        NUM_ELEM(localagent_cert_getfingerprint_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_LocalAgent_ReqChallenge_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.LocalAgent.ControllerTrust.RequestChallenge()",
                                      uspd_operate_sync);
    err |= USP_REGISTER_OperationArguments("Device.LocalAgent.ControllerTrust.RequestChallenge()",
                                        localagent_reqchallenge_input_args,
                                        NUM_ELEM(localagent_reqchallenge_input_args),
                                        localagent_reqchallenge_output_args,
                                        NUM_ELEM(localagent_reqchallenge_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_LocalAgent_ChallengeResp_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.LocalAgent.ControllerTrust.ChallengeResponse()",
                                      uspd_operate_sync);
    err |= USP_REGISTER_OperationArguments("Device.LocalAgent.ControllerTrust.ChallengeResponse()",
                                        localagent_challengeresp_input_args,
                                        NUM_ELEM(localagent_challengeresp_input_args),
                                        NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_MQTT_ForceReconnect_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.MQTT.Client.{i}.ForceReconnect()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_MQTT_Broker_ForceReconnect_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.MQTT.Broker.{i}.Bridge.{i}.ForceReconnect()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_SWModules_SetRunLevel_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.SoftwareModules.ExecEnv.{i}.SetRunLevel()",
                                      uspd_operate_sync);
    err |= USP_REGISTER_OperationArguments("Device.SoftwareModules.ExecEnv.{i}.SetRunLevel()",
                                        swmodules_setrunlevel_input_args,
                                        NUM_ELEM(swmodules_setrunlevel_input_args),
                                        NULL, 0);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_SWModules_Reset_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.SoftwareModules.ExecEnv.{i}.Reset()",
                                      uspd_operate_sync);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

int Device_SWModules_SetReqState_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_SyncOperation("Device.SoftwareModules.ExecutionUnit.{i}.SetRequestedState()",
                                      uspd_operate_sync);
    err |= USP_REGISTER_OperationArguments("Device.SoftwareModules.ExecutionUnit.{i}.SetRequestedState()",
                                        swmodules_setreqstate_input_args,
                                        NUM_ELEM(swmodules_setreqstate_input_args),
                                        NULL, 0);

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
    err |= Device_DSL_ADSLLinetest_Init();
    err |= Device_DSL_SELTUER_Init();
    err |= Device_DSL_SELTQLN_Init();
    err |= Device_DSL_SELTP_Init();
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
    err |= MTP_WebSocket_Reset_Init();
    err |= E2ESession_Reset_Init();
	err |= SWModules_DeployUnit_Uninstall_Init();
    return err;
}

int vendor_operate_sync_init(void)
{
    int err = USP_ERR_OK;

    err |= Device_TempSensor_Reset_Init();
    err |= Device_UserInterface_PasswdReset_Init();
    err |= Device_USBHost_Reset_Init();
    err |= Device_WiFi_Reset_Init();
    err |= Device_AP_Security_Reset_Init();
    err |= Device_PPP_Reset_Init();
    err |= Device_IPInterface_Reset_Init();
    err |= Device_DHCPv4_Renew_Init();
    err |= Device_DHCPv6_Renew_Init();
    err |= Device_IEEE8021x_Reset_Init();
    err |= Device_IEEE8021x_Disconnect_Init();
    err |= Device_SmartCardReader_Reset_Init();
    err |= Device_SampleSet_ForceSample_Init();
    err |= Device_FAP_GPSReset_Init();
    err |= Device_LocalAgent_AddCerts_Init();
    err |= Device_Controller_SchTimer_Init();
    err |= Device_Controller_AddCerts_Init();
    err |= Device_Controller_SendOnBoardReq_Init();
    err |= Device_LocalAgent_ReqCancel_Init();
    err |= Device_LocalAgent_CertsDelete_Init();
    err |= Device_LocalAgent_GetFingerPrint_Init();
    err |= Device_LocalAgent_ReqChallenge_Init();
    err |= Device_LocalAgent_ChallengeResp_Init();
    err |= Device_MQTT_ForceReconnect_Init();
    err |= Device_MQTT_Broker_ForceReconnect_Init();
    err |= Device_SWModules_SetRunLevel_Init();
    err |= Device_SWModules_Reset_Init();
    err |= Device_SWModules_SetReqState_Init();

    return err;
}
