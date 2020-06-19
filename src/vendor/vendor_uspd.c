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
#include "text_utils.h"

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

// Timeout in milliseconds
#define USP_PROTO "usp"
#define USPD_TIMEOUT 5000
#define ASYNC_USPD_TIMEOUT 30000
#define INST_MONITOR_TIMER (60)

extern bool is_running_cli_local_command;

typedef void (*UBUS_USP_CB) (struct ubus_request *req, int type, struct blob_attr *msg);

typedef struct
{
    // Instance number of this operation in the Device.LocalAgent.Request table
    int request_instance;
    char path[MAX_DM_PATH];
    kv_vector_t *input_args;
} input_cond_t;

static str_vector_t gs_async_paths;
static str_vector_t g_inst_vector;

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

static int get_schema_path(char *path, char *schema)
{
	char *temp;
	char *tok, *save;
	size_t tlen;

	tlen =  strlen(path);
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
	if (path[tlen - 1] == '.') {
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

int uspd_operate_async(dm_req_t *req, kv_vector_t *input_args, int instance)
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

static void vendor_uniq_key_init(kv_vector_t *kv)
{
	if (kv == NULL)
		return;

	USP_ARG_Add(kv, "Device.DeviceInfo.VendorConfigFile.{i}", "Name");
	USP_ARG_Add(kv, "Device.DeviceInfo.ProcessStatus.Process.{i}", "PID");
	USP_ARG_Add(kv, "Device.DeviceInfo.TemperatureStatus.TemperatureSensor.{i}", "Name");
	USP_ARG_Add(kv, "Device.DeviceInfo.VendorLogFile.{i}", "Name");
	USP_ARG_Add(kv, "Device.DeviceInfo.Location.{i}", "Source;ExternalSource");
	USP_ARG_Add(kv, "Device.LEDs.LED.{i}.CycleElement.{i}", "Order");
	USP_ARG_Add(kv, "Device.BASAPM.MeasurementEndpoint.{i}", "MeasurementAgent");
	USP_ARG_Add(kv, "Device.DeviceInfo.DeviceImageFile.{i}", "Location");
	USP_ARG_Add(kv, "Device.DeviceInfo.FirmwareImage.{i}", "Name");
	USP_ARG_Add(kv, "Device.DSL.Line.{i}", "Name");
	USP_ARG_Add(kv, "Device.DSL.Channel.{i}", "Name");
	USP_ARG_Add(kv, "Device.DSL.BondingGroup.{i}", "Name");
	USP_ARG_Add(kv, "Device.DSL.BondingGroup.{i}.BondedChannel.{i}", "Channel");
	USP_ARG_Add(kv, "Device.FAST.Line.{i}", "Name");
	USP_ARG_Add(kv, "Device.Optical.Interface.{i}", "Name");
	USP_ARG_Add(kv, "Device.Cellular.Interface.{i}","Name");
	USP_ARG_Add(kv, "Device.Cellular.AccessPoint.{i}", "Interface");
	USP_ARG_Add(kv, "Device.ATM.Link.{i}", "Name");
	USP_ARG_Add(kv, "Device.PTM.Link.{i}", "Name");
	USP_ARG_Add(kv, "Device.Ethernet.Interface.{i}", "Name");
	USP_ARG_Add(kv, "Device.Ethernet.Link.{i}", "Name;MACAddress");
	USP_ARG_Add(kv, "Device.Ethernet.VLANTermination.{i}", "Name");
	USP_ARG_Add(kv, "Device.Ethernet.RMONStats.{i}", "Name");
	USP_ARG_Add(kv, "Device.Ethernet.LAG.{i}", "Name");
	USP_ARG_Add(kv, "Device.USB.Interface.{i}", "Name");
	USP_ARG_Add(kv, "Device.USB.Port.{i}", "Name");
	USP_ARG_Add(kv, "Device.USB.USBHosts.Host.{i}", "Name");
	USP_ARG_Add(kv, "Device.USB.USBHosts.Host.{i}.Device.{i}", "DeviceNumber");
	USP_ARG_Add(kv, "Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}", "ConfigurationNumber");
	USP_ARG_Add(kv, "Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}.Interface.{i}", "InterfaceNumber");
	USP_ARG_Add(kv, "Device.HPNA.Interface.{i}", "Name");
	USP_ARG_Add(kv, "Device.HPNA.Interface.{i}.AssociatedDevice.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.MoCA.Interface.{i}.QoS.FlowStats.{i}", "FlowID");
	USP_ARG_Add(kv, "Device.MoCA.Interface.{i}.AssociatedDevice.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.Ghn.Interface.{i}.AssociatedDevice.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.Ghn.Interface.{i}.SMMaskedBand.{i}", "BandNumber");
	USP_ARG_Add(kv, "Device.HomePlug.Interface.{i}.AssociatedDevice.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.UPA.Interface.{i}.AssociatedDevice.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.UPA.Interface.{i}.BridgeFor.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.WiFi.Radio.{i}", "Name");
	USP_ARG_Add(kv, "Device.WiFi.SSID.{i}", "Name;BSSID");
	USP_ARG_Add(kv, "Device.WiFi.AccessPoint.{i}", "SSIDReference");
	USP_ARG_Add(kv, "Device.WiFi.AccessPoint"".{i}.AssociatedDevice.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.WiFi.AccessPoint"".{i}.AC.{i}", "AccessCategory");
	USP_ARG_Add(kv, "Device.WiFi.EndPoint.{i}", "SSIDReference");
	USP_ARG_Add(kv, "Device.WiFi.EndPoint.{i}.Profile.{i}", "SSID");
	USP_ARG_Add(kv, "Device.WiFi.EndPoint"".{i}.AC.{i}", "AccessCategory");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDevice.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.AP.{i}", "BSSID");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.AP.{i}.AssociatedDevice.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.AP.{i}.AssociatedDevice.{i}.SteeringHistory.{i}", "Time;APOrigin;APDestination");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}", "ID");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}", "ID");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}", "Class");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}", "Class");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}", "BSSID");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}", "OperatingClass");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}", "Channel");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}", "BSSID");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}", "MACAddress");
	USP_ARG_Add(kv, "Device.ZigBee.Interface.{i}.AssociatedDevice.{i}", "IEEEAddress;NetworkAddress");
	USP_ARG_Add(kv, "Device.ZigBee.ZDO.{i}", "IEEEAddress;NetworkAddress");
	USP_ARG_Add(kv, "Device.ZigBee.ZDO.{i}.Network.Neighbor.{i}", "Neighbor");
	USP_ARG_Add(kv, "Device.ZigBee.ZDO.{i}.NodeManager.RoutingTable.{i}", "DestinationAddress");
	USP_ARG_Add(kv, "Device.Bridging.Bridge.{i}.Port.{i}", "Name");
	USP_ARG_Add(kv, "Device.Bridging.Bridge.{i}.VLAN.{i}", "VLANID");
	USP_ARG_Add(kv, "Device.Bridging.Bridge.{i}.VLANPort.{i}", "VLAN;Port");
	USP_ARG_Add(kv, "Device.PPP.Interface.{i}", "Name");
	USP_ARG_Add(kv, "Device.IP.Interface.{i}", "Name");
	USP_ARG_Add(kv, "Device.IP.Interface.{i}.IPv4Address.{i}", "IPAddress;SubnetMask");
	USP_ARG_Add(kv, "Device.IP.Interface.{i}.IPv6Address.{i}", "IPAddress;Prefix");
	USP_ARG_Add(kv, "Device.IP.Interface.{i}.IPv6Prefix.{i}", "Prefix");
	USP_ARG_Add(kv, "Device.IP.ActivePort.{i}", "LocalIPAddress;LocalPort;RemoteIPAddress;RemotePort");
	USP_ARG_Add(kv, "Device.LLDP.Discovery.Device.{i}", "ChassisIDSubtype;ChassisID");
	USP_ARG_Add(kv, "Device.LLDP.Discovery.Device.{i}.Port.{i}", "PortIDSubtype;PortID");
	USP_ARG_Add(kv, "Device.LLDP.Discovery.Device.{i}.DeviceInformation.VendorSpecific.{i}", "OrganizationCode;InformationType");
	USP_ARG_Add(kv, "Device.IPsec.Profile.{i}.SentCPAttr.{i}", "Type");
	USP_ARG_Add(kv, "Device.IPsec.Tunnel.{i}", "TunnelInterface;TunneledInterface");
	USP_ARG_Add(kv, "Device.IPsec.IKEv2SA.{i}", "Tunnel");
	USP_ARG_Add(kv, "Device.GRE.Tunnel.{i}.Interface.{i}", "Name");
	USP_ARG_Add(kv, "Device.VXLAN.Tunnel.{i}.Interface.{i}", "Name");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}", "Identifier");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.TaskCapability.{i}", "Name");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.TaskCapability.{i}.Registry.{i}", "RegistryEntry");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Schedule.{i}", "Name");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Schedule.{i}.Action.{i}.Option.{i}", "Name");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Task.{i}", "Name");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Task.{i}.Registry.{i}", "RegistryEntry");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Task.{i}.Option.{i}", "Name");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.CommunicationChannel.{i}", "Name");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Instruction.{i}.MeasurementSuppression.{i}", "Name");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.Result.{i}", "ScheduleName;ActionName;StartTime");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.Result.{i}.Option.{i}", "Name");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.Result.{i}.Conflict.{i}", "ScheduleName;ActionName;TaskName");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.Result.{i}.ReportTable.{i}.Registry.{i}", "RegistryEntry");
	USP_ARG_Add(kv, "Device.LMAP.Event.{i}", "Name");
	USP_ARG_Add(kv, "Device.SoftwareModules.ExecEnv.{i}", "Name");
	USP_ARG_Add(kv, "Device.SoftwareModules.DeploymentUnit.{i}", "UUID;Version;ExecutionEnvRef");
	USP_ARG_Add(kv, "Device.SoftwareModules.ExecutionUnit.{i}", "EUID");
	USP_ARG_Add(kv, "Device.IoTCapability.{i}", "Name");
	USP_ARG_Add(kv, "Device.Routing.Router.{i}.IPv4Forwarding.{i}", "DestIPAddress;DestSubnetMask;ForwardingPolicy;GatewayIPAddress;Interface;ForwardingMetric");
	USP_ARG_Add(kv, "Device.Routing.Router.{i}.IPv6Forwarding.{i}", "DestIPPrefix;ForwardingPolicy;NextHop;Interface;ForwardingMetric");
	USP_ARG_Add(kv, "Device.Routing.RouteInformation.InterfaceSetting.{i}", "Interface");
	USP_ARG_Add(kv, "Device.NeighborDiscovery.InterfaceSetting.{i}", "Interface");
	USP_ARG_Add(kv, "Device.RouterAdvertisement.InterfaceSetting.{i}", "Interface");
	USP_ARG_Add(kv, "Device.RouterAdvertisement.InterfaceSetting.{i}.Option.{i}", "Tag");
	USP_ARG_Add(kv, "Device.QoS.Shaper.{i}", "Interface");
	USP_ARG_Add(kv, "Device.Hosts.Host.{i}", "PhysAddress");
	USP_ARG_Add(kv, "Device.Hosts.Host.{i}.IPv4Address.{i}", "IPAddress");
	USP_ARG_Add(kv, "Device.Hosts.Host.{i}.IPv6Address.{i}", "IPAddress");
	USP_ARG_Add(kv, "Device.DNS.Client.Server.{i}", "DNSServer");
	USP_ARG_Add(kv, "Device.DNS.Relay.Forwarding.{i}", "DNSServer");
	USP_ARG_Add(kv, "Device.DNS.SD.Service.{i}", "InstanceName");
	USP_ARG_Add(kv, "Device.DNS.SD.Service.{i}.TextRecord.{i}", "Key");
	USP_ARG_Add(kv, "Device.NAT.InterfaceSetting.{i}", "Interface");
	USP_ARG_Add(kv, "Device.NAT.PortMapping.{i}", "RemoteHost;ExternalPort;Protocol");
	USP_ARG_Add(kv, "Device.DHCPv4.Client.{i}", "Interface");
	USP_ARG_Add(kv, "Device.DHCPv4.Client.{i}.SentOption.{i}", "Tag");
	USP_ARG_Add(kv, "Device.DHCPv4.Client.{i}.ReqOption.{i}", "Tag");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}", "Chaddr");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.Option.{i}", "Tag");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.Client.{i}", "Chaddr");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.Client.{i}.IPv4Address.{i}", "IPAddress");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.Client.{i}.Option.{i}", "Tag");
	USP_ARG_Add(kv, "Device.DHCPv6.Client.{i}", "Interface");
	USP_ARG_Add(kv, "Device.DHCPv6.Client.{i}.Server.{i}", "SourceAddress");
	USP_ARG_Add(kv, "Device.DHCPv6.Client.{i}.SentOption.{i}", "Tag");
	USP_ARG_Add(kv, "Device.DHCPv6.Client.{i}.ReceivedOption.{i}", "Tag");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}", "Order");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.Client.{i}", "SourceAddress");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Address.{i}", "IPAddress");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Prefix.{i}", "Prefix");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.Client.{i}.Option.{i}", "Tag");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.Option.{i}", "Tag");
	USP_ARG_Add(kv, "Device.Users.User.{i}", "Username");
	USP_ARG_Add(kv, "Device.SmartCardReaders.SmartCardReader.{i}", "Name");
	USP_ARG_Add(kv, "Device.UPnP.Discovery.RootDevice.{i}", "UUID");
	USP_ARG_Add(kv, "Device.UPnP.Discovery.Device.{i}", "UUID");
	USP_ARG_Add(kv, "Device.UPnP.Discovery.Service.{i}", "USN");
	USP_ARG_Add(kv, "Device.UPnP.Description.DeviceDescription.{i}", "URLBase");
	USP_ARG_Add(kv, "Device.UPnP.Description.DeviceInstance.{i}", "UDN");
	USP_ARG_Add(kv, "Device.UPnP.Description.ServiceInstance.{i}", "ParentDevice;ServiceId");
	USP_ARG_Add(kv, "Device.Firewall.Level.{i}", "Name");
	USP_ARG_Add(kv, "Device.Firewall.Chain.{i}", "Name");
	USP_ARG_Add(kv, "Device.PeriodicStatistics.SampleSet.{i}", "Name");
	USP_ARG_Add(kv, "Device.PeriodicStatistics.SampleSet.{i}.Parameter.{i}", "Reference");
	USP_ARG_Add(kv, "Device.FaultMgmt.SupportedAlarm.{i}", "EventType;ProbableCause;SpecificProblem;PerceivedSeverity");
	USP_ARG_Add(kv, "Device.FaultMgmt.CurrentAlarm.{i}", "AlarmIdentifier");
	USP_ARG_Add(kv, "Device.FaultMgmt.HistoryEvent.{i}", "EventTime;AlarmIdentifier");
	USP_ARG_Add(kv, "Device.FaultMgmt.ExpeditedEvent.{i}", "AlarmIdentifier");
	USP_ARG_Add(kv, "Device.FaultMgmt.QueuedEvent.{i}", "AlarmIdentifier");
	USP_ARG_Add(kv, "Device.FAP.PerfMgmt.Config.{i}", "URL;PeriodicUploadInterval;PeriodicUploadTime");
	USP_ARG_Add(kv, "Device.XMPP.Connection.{i}", "Username;Domain;Resource");
	USP_ARG_Add(kv, "Device.XMPP.Connection.{i}.Server.{i}", "ServerAddress;Port");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.Interface.{i}", "InterfaceId");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.Interface.{i}.Link.{i}", "InterfaceId;IEEE1905Id");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}", "IEEE1905Id");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}", "MACAddress;IPv4Address");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}", "MACAddress;IPv6Address");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}", "InterfaceId");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}", "LocalInterface;NeighborInterfaceId");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.L2Neighbor.{i}", "LocalInterface;NeighborInterfaceId");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}", "LocalInterface;NeighborDeviceId");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}", "NeighborMACAddress");
	USP_ARG_Add(kv, "Device.DynamicDNS.Client.{i}", "Server;Username");
	USP_ARG_Add(kv, "Device.DynamicDNS.Client.{i}.Hostname.{i}", "Name");
	USP_ARG_Add(kv, "Device.DynamicDNS.Server.{i}", "Name");
	USP_ARG_Add(kv, "Device.LEDs.LED.{i}", "Name");
}

static void vendor_num_entries_init(kv_vector_t *kv)
{
	USP_ARG_Add(kv, "Device.DeviceInfo.VendorConfigFileNumberOfEntries", "Device.DeviceInfo.VendorConfigFile.{i}");
	USP_ARG_Add(kv, "Device.DeviceInfo.ProcessStatus.ProcessNumberOfEntries", "Device.DeviceInfo.ProcessStatus.Process.{i}");
	USP_ARG_Add(kv, "Device.DeviceInfo.TemperatureStatus.TemperatureSensorNumberOfEntries", "Device.DeviceInfo.TemperatureStatus.TemperatureSensor.{i}");
	USP_ARG_Add(kv, "Device.DeviceInfo.ProcessorNumberOfEntries", "Device.DeviceInfo.Processor.{i}");
	USP_ARG_Add(kv, "Device.DeviceInfo.VendorLogFileNumberOfEntries", "Device.DeviceInfo.VendorLogFile.{i}");
	USP_ARG_Add(kv, "Device.DeviceInfo.LocationNumberOfEntries", "Device.DeviceInfo.Processor.{i}");
	USP_ARG_Add(kv, "Device.DeviceInfo.DeviceImageNumberOfEntries", "Device.DeviceInfo.DeviceImageFile.{i}");
	USP_ARG_Add(kv, "Device.DeviceInfo.FirmwareImageNumberOfEntries", "Device.DeviceInfo.FirmwareImage.{i}");
	USP_ARG_Add(kv, "Device.InterfaceStackNumberOfEntries", "Device.InterfaceStack.{i}");
	USP_ARG_Add(kv, "Device.DSL.LineNumberOfEntries", "Device.DSL.Line.{i}");
	USP_ARG_Add(kv, "Device.DSL.ChannelNumberOfEntries", "Device.DSL.Channel.{i}");
	USP_ARG_Add(kv, "Device.DSL.BondingGroupNumberOfEntries", "Device.DSL.BondingGroup.{i}");
	USP_ARG_Add(kv, "Device.DSL.BondingGroup.{i}.BondedChannelNumberOfEntries", "Device.DSL.BondingGroup.{i}.BondedChannel.{i}");
	USP_ARG_Add(kv, "Device.FAST.LineNumberOfEntries", "Device.FAST.Line.{i}");
	USP_ARG_Add(kv, "Device.Optical.InterfaceNumberOfEntries", "Device.Optical.Interface.{i}");
	USP_ARG_Add(kv, "Device.Cellular.InterfaceNumberOfEntries", "Device.Cellular.Interface.{i}");
	USP_ARG_Add(kv, "Device.Cellular.AccessPointNumberOfEntries", "Device.Cellular.AccessPoint.{i}");
	USP_ARG_Add(kv, "Device.ATM.LinkNumberOfEntries", "Device.ATM.Link.{i}");
	USP_ARG_Add(kv, "Device.PTM.LinkNumberOfEntries", "Device.PTM.Link.{i}");
	USP_ARG_Add(kv, "Device.Ethernet.InterfaceNumberOfEntries", "Device.Ethernet.Interface.{i}");
	USP_ARG_Add(kv, "Device.Ethernet.LinkNumberOfEntries", "Device.Ethernet.Link.{i}");
	USP_ARG_Add(kv, "Device.Ethernet.VLANTerminationNumberOfEntries", "Device.Ethernet.VLANTermination.{i}");
	USP_ARG_Add(kv, "Device.Ethernet.RMONStatsNumberOfEntries", "Device.Ethernet.RMONStats.{i}");
	USP_ARG_Add(kv, "Device.Ethernet.LAGNumberOfEntries", "Device.Ethernet.LAG.{i}");
	USP_ARG_Add(kv, "Device.USB.InterfaceNumberOfEntries", "Device.USB.Interface.{i}");
	USP_ARG_Add(kv, "Device.USB.PortNumberOfEntries", "Device.USB.Port.{i}");
	USP_ARG_Add(kv, "Device.USB.USBHosts.HostNumberOfEntries", "Device.USB.USBHosts.Host.{i}");
	USP_ARG_Add(kv, "Device.USB.USBHosts.Host.{i}.DeviceNumberOfEntries", "Device.USB.USBHosts.Host.{i}.Device.{i}");
	USP_ARG_Add(kv, "Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}.InterfaceNumberOfEntries", "Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}.Interface.{i}");
	USP_ARG_Add(kv, "Device.HPNA.InterfaceNumberOfEntries", "Device.HPNA.Interface.{i}");
	USP_ARG_Add(kv, "Device.HPNA.Interface.{i}.QoS.FlowSpecNumberOfEntries", "Device.HPNA.Interface.{i}.QoS.FlowSpec.{i}");
	USP_ARG_Add(kv, "Device.HPNA.Interface.{i}.AssociatedDeviceNumberOfEntries", "Device.HPNA.Interface.{i}.AssociatedDevice.{i}");
	USP_ARG_Add(kv, "Device.MoCA.InterfaceNumberOfEntries", "Device.MoCA.Interface.{i}");
	USP_ARG_Add(kv, "Device.MoCA.Interface.{i}.QoS.FlowStatsNumberOfEntries", "Device.MoCA.Interface.{i}.QoS.FlowStats.{i}");
	USP_ARG_Add(kv, "Device.MoCA.Interface.{i}.AssociatedDeviceNumberOfEntries", "Device.MoCA.Interface.{i}.AssociatedDevice.{i}");
	USP_ARG_Add(kv, "Device.Ghn.InterfaceNumberOfEntries", "Device.Ghn.Interface.{i}");
	USP_ARG_Add(kv, "Device.Ghn.Interface.{i}.AssociatedDeviceNumberOfEntries", "Device.Ghn.Interface.{i}.AssociatedDevice.{i}");
	USP_ARG_Add(kv, "Device.Ghn.Interface.{i}.SMMaskedBandNumberOfEntries", "Device.Ghn.Interface.{i}.SMMaskedBand.{i}");
	USP_ARG_Add(kv, "Device.HomePlug.InterfaceNumberOfEntries", "Device.HomePlug.Interface.{i}");
	USP_ARG_Add(kv, "Device.HomePlug.Interface.{i}.AssociatedDeviceNumberOfEntries", "Device.HomePlug.Interface.{i}.AssociatedDevice.{i}");
	USP_ARG_Add(kv, "Device.UPA.InterfaceNumberOfEntries", "Device.UPA.Interface.{i}");
	USP_ARG_Add(kv, "Device.UPA.Interface.{i}.AssociatedDeviceNumberOfEntries", "Device.UPA.Interface.{i}.AssociatedDevice.{i}");
	USP_ARG_Add(kv, "Device.UPA.Interface.{i}.ActiveNotchNumberOfEntries", "Device.UPA.Interface.{i}.ActiveNotch.{i}");
	USP_ARG_Add(kv, "Device.UPA.Interface.{i}.BridgeForNumberOfEntries", "Device.UPA.Interface.{i}.BridgeFor.{i}");
	USP_ARG_Add(kv, "Device.WiFi.RadioNumberOfEntries", "Device.WiFi.Radio.{i}");
	USP_ARG_Add(kv, "Device.WiFi.SSIDNumberOfEntries", "Device.WiFi.SSID.{i}");
	USP_ARG_Add(kv, "Device.WiFi.AccessPointNumberOfEntries", "Device.WiFi.AccessPoint.{i}");
	USP_ARG_Add(kv, "Device.WiFi.AccessPoint.{i}.AssociatedDeviceNumberOfEntries", "Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}");
	USP_ARG_Add(kv, "Device.WiFi.EndPointNumberOfEntries", "Device.WiFi.EndPoint.{i}");
	USP_ARG_Add(kv, "Device.WiFi.EndPoint.{i}.ProfileNumberOfEntries", "Device.WiFi.EndPoint.{i}.Profile.{i}");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDeviceNumberOfEntries", "Device.WiFi.MultiAP.APDevice.{i}");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDevice.{i}.RadioNumberOfEntries", "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.APNumberOfEntries", "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.AP.{i}");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.AP.{i}.AssociatedDeviceNumberOfEntries", "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.AP.{i}.AssociatedDevice.{i}");
	USP_ARG_Add(kv, "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.AP.{i}.AssociatedDevice.{i}.SteeringHistoryNumberOfEntries", "Device.WiFi.MultiAP.APDevice.{i}.Radio.{i}.AP.{i}.AssociatedDevice.{i}.SteeringHistory.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.DeviceNumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.RadioNumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfileNumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfileNumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSSNumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STANumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResultNumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScanNumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScanNumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSSNumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTANumberOfEntries", "Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.AssociationEvent.AssociationEventDataNumberOfEntries", "Device.WiFi.DataElements.AssociationEvent.AssociationEventData.{i}");
	USP_ARG_Add(kv, "Device.WiFi.DataElements.DisassociationEvent.DisassociationEventDataNumberOfEntries", "Device.WiFi.DataElements.DisassociationEvent.DisassociationEventData.{i}");
	USP_ARG_Add(kv, "Device.ZigBee.InterfaceNumberOfEntries", "Device.ZigBee.Interface.{i}");
	USP_ARG_Add(kv, "Device.ZigBee.Interface.{i}.AssociatedDeviceNumberOfEntries", "Device.ZigBee.Interface.{i}.AssociatedDevice.{i}");
	USP_ARG_Add(kv, "Device.ZigBee.ZDONumberOfEntries", "Device.ZigBee.ZDO.{i}");
	USP_ARG_Add(kv, "Device.ZigBee.ZDO.{i}.Network.NeighborNumberOfEntries", "Device.ZigBee.ZDO.{i}.Network.Neighbor.{i}");
	USP_ARG_Add(kv, "Device.ZigBee.ZDO.{i}.NodeManager.RoutingTableNumberOfEntries", "Device.ZigBee.ZDO.{i}.NodeManager.RoutingTable.{i}");
	USP_ARG_Add(kv, "Device.ZigBee.ZDO.{i}.BindingTableNumberOfEntries", "Device.ZigBee.ZDO.{i}.Binding..{i}");
	USP_ARG_Add(kv, "Device.ZigBee.ZDO.{i}.GroupNumberOfEntries", "Device.ZigBee.ZDO.{i}.Group.{i}");
	USP_ARG_Add(kv, "Device.ZigBee.ZDO.{i}.ApplicationEndpointNumberOfEntries", "Device.ZigBee.ZDO.{i}.ApplicationEndpoint.{i}");
	USP_ARG_Add(kv, "Device.ZigBee.Discovery.AreaNetworkNumberOfEntries", "Device.ZigBee.Discovery.AreaNetwork.{i}");
	USP_ARG_Add(kv, "Device.Bridging.BridgeNumberOfEntries", "Device.Bridging.Bridge.{i}");
	USP_ARG_Add(kv, "Device.Bridging.Bridge.{i}.PortNumberOfEntries", "Device.Bridging.Bridge.{i}.Port.{i}");
	USP_ARG_Add(kv, "Device.Bridging.Bridge.{i}.VLANNumberOfEntries", "Device.Bridging.Bridge.{i}.VLAN.{i}");
	USP_ARG_Add(kv, "Device.Bridging.Bridge.{i}.VLANPortNumberOfEntries", "Device.Bridging.Bridge.{i}.VLANPort.{i}");
	USP_ARG_Add(kv, "Device.Bridging.FilterNumberOfEntries", "Device.Bridging.Filter.{i}");
	USP_ARG_Add(kv, "Device.Bridging.ProviderBridgeNumberOfEntries", "Device.Bridging.ProviderBridge.{i}");
	USP_ARG_Add(kv, "Device.PPP.InterfaceNumberOfEntries", "Device.PPP.Interface.{i}");
	USP_ARG_Add(kv, "Device.IP.InterfaceNumberOfEntries", "Device.IP.Interface.{i}");
	USP_ARG_Add(kv, "Device.IP.Interface.{i}.IPv4AddressNumberOfEntries", "Device.IP.Interface.{i}.IPv4Address.{i}");
	USP_ARG_Add(kv, "Device.IP.Interface.{i}.TWAMPReflectorNumberOfEntries", "Device.IP.Interface.{i}.TWAMPReflector.{i}");
	USP_ARG_Add(kv, "Device.IP.Interface.{i}.IPv6AddressNumberOfEntries", "Device.IP.Interface.{i}.IPv6Address.{i}");
	USP_ARG_Add(kv, "Device.IP.Interface.{i}.IPv6PrefixNumberOfEntries", "Device.IP.Interface.{i}.IPv6Prefix.{i}");
	USP_ARG_Add(kv, "Device.IP.ActivePortNumberOfEntries", "Device.IP.ActivePort.{i}");
	USP_ARG_Add(kv, "Device.LLDP.Discovery.DeviceNumberOfEntries", "Device.LLDP.Discovery.Device.{i}");
	USP_ARG_Add(kv, "Device.LLDP.Discovery.Device.{i}.PortNumberOfEntries", "Device.LLDP.Discovery.Device.{i}.Port.{i}");
	USP_ARG_Add(kv, "Device.LLDP.Discovery.Device.{i}.DeviceInformation.VendorSpecificNumberOfEntries", "Device.LLDP.Discovery.Device.{i}.DeviceInformation.VendorSpecific.{i}");
	USP_ARG_Add(kv, "Device.IPsec.FilterNumberOfEntries", "Device.IPsec.Filter.{i}");
	USP_ARG_Add(kv, "Device.IPsec.ProfileNumberOfEntries", "Device.IPsec.Profile.{i}");
	USP_ARG_Add(kv, "Device.IPsec.Profile.{i}.SentCPAttrNumberOfEntries", "Device.IPsec.Profile.{i}.SentCPAttr.{i}");
	USP_ARG_Add(kv, "Device.IPsec.TunnelNumberOfEntries", "Device.IPsec.Tunnel.{i}");
	USP_ARG_Add(kv, "Device.IPsec.IKEv2SANumberOfEntries", "Device.IPsec.IKEv2SA.{i}");
	USP_ARG_Add(kv, "Device.IPsec.IKEv2SA.{i}.ReceivedCPAttrNumberOfEntries", "Device.IPsec.IKEv2SA.{i}.ReceivedCPAttr.{i}");
	USP_ARG_Add(kv, "Device.IPsec.IKEv2SA.{i}.ChildSANumberOfEntries", "Device.IPsec.IKEv2SA.{i}.ChildSA.{i}");
	USP_ARG_Add(kv, "Device.GRE.TunnelNumberOfEntries", "Device.GRE.Tunnel.{i}");
	USP_ARG_Add(kv, "Device.GRE.Tunnel.{i}.InterfaceNumberOfEntries", "Device.GRE.Tunnel.{i}.Interface.{i}");
	USP_ARG_Add(kv, "Device.GRE.FilterNumberOfEntries", "Device.GRE.Filter.{i}");
	USP_ARG_Add(kv, "Device.L2TPv3.TunnelNumberOfEntries", "Device.L2TPv3.Tunnel.{i}");
	USP_ARG_Add(kv, "Device.L2TPv3.Tunnel.{i}.InterfaceNumberOfEntries", "Device.L2TPv3.Tunnel.{i}.Interface.{i}");
	USP_ARG_Add(kv, "Device.L2TPv3.FilterNumberOfEntries", "Device.L2TPv3.Filter.{i}");
	USP_ARG_Add(kv, "Device.VXLAN.TunnelNumberOfEntries", "Device.VXLAN.Tunnel.{i}");
	USP_ARG_Add(kv, "Device.VXLAN.Tunnel.{i}.InterfaceNumberOfEntries", "Device.VXLAN.Tunnel.{i}.Interface.{i}");
	USP_ARG_Add(kv, "Device.VXLAN.FilterNumberOfEntries", "Device.VXLAN.Filter.{i}");
	USP_ARG_Add(kv, "Device.MAP.DomainNumberOfEntries", "Device.MAP.Domain.{i}");
	USP_ARG_Add(kv, "Device.MAP.Domain.{i}.RuleNumberOfEntries", "Device.MAP.Domain.{i}.Rule.{i}");
	USP_ARG_Add(kv, "Device.Routing.RouterNumberOfEntries", "Device.Routing.Router.{i}");
	USP_ARG_Add(kv, "Device.Routing.Router.{i}.IPv4ForwardingNumberOfEntries", "Device.Routing.Router.{i}.IPv4Forwarding.{i}");
	USP_ARG_Add(kv, "Device.Routing.Router.{i}.IPv6ForwardingNumberOfEntries", "Device.Routing.Router.{i}.IPv6Forwarding.{i}");
	USP_ARG_Add(kv, "Device.Routing.RIP.InterfaceSettingNumberOfEntries", "Device.Routing.RIP.InterfaceSetting.{i}");
	USP_ARG_Add(kv, "Device.Routing.RouteInformation.InterfaceSettingNumberOfEntries", "Device.Routing.RouteInformation.InterfaceSetting.{i}");
	USP_ARG_Add(kv, "Device.NeighborDiscovery.InterfaceSettingNumberOfEntries", "Device.NeighborDiscovery.InterfaceSetting.{i}");
	USP_ARG_Add(kv, "Device.RouterAdvertisement.InterfaceSettingNumberOfEntries", "Device.RouterAdvertisement.InterfaceSetting.{i}");
	USP_ARG_Add(kv, "Device.RouterAdvertisement.InterfaceSetting.{i}.OptionNumberOfEntries", "Device.RouterAdvertisement.InterfaceSetting.{i}.Option.{i}");
	USP_ARG_Add(kv, "Device.IPv6rd.InterfaceSettingNumberOfEntries", "Device.IPv6rd.InterfaceSetting.{i}");
	USP_ARG_Add(kv, "Device.DSLite.InterfaceSettingNumberOfEntries", "Device.DSLite.InterfaceSetting.{i}");
	USP_ARG_Add(kv, "Device.QoS.ClassificationNumberOfEntries", "Device.QoS.Classification.{i}");
	USP_ARG_Add(kv, "Device.QoS.AppNumberOfEntries", "Device.QoS.App.{i}");
	USP_ARG_Add(kv, "Device.QoS.FlowNumberOfEntries", "Device.QoS.Flow.{i}");
	USP_ARG_Add(kv, "Device.QoS.PolicerNumberOfEntries", "Device.QoS.Policer.{i}");
	USP_ARG_Add(kv, "Device.QoS.QueueNumberOfEntries", "Device.QoS.Queue.{i}");
	USP_ARG_Add(kv, "Device.QoS.QueueStatsNumberOfEntries", "Device.QoS.QueueStats.{i}");
	USP_ARG_Add(kv, "Device.QoS.ShaperNumberOfEntries", "Device.QoS.Shaper.{i}");
	USP_ARG_Add(kv, "Device.Hosts.HostNumberOfEntries", "Device.Hosts.Host.{i}");
	USP_ARG_Add(kv, "Device.Hosts.Host.{i}.IPv4AddressNumberOfEntries", "Device.Hosts.Host.{i}.IPv4Address.{i}");
	USP_ARG_Add(kv, "Device.Hosts.Host.{i}.IPv6AddressNumberOfEntries", "Device.Hosts.Host.{i}.IPv6Address.{i}");
	USP_ARG_Add(kv, "Device.DNS.Client.ServerNumberOfEntries", "Device.DNS.Client.Server.{i}");
	USP_ARG_Add(kv, "Device.DNS.Relay.ForwardNumberOfEntries", "Device.DNS.Relay.Forwarding.{i}");
	USP_ARG_Add(kv, "Device.DNS.SD.ServiceNumberOfEntries", "Device.DNS.SD.Service.{i}");
	USP_ARG_Add(kv, "Device.DNS.SD.Service.{i}.TextRecordNumberOfEntries", "Device.DNS.SD.Service.{i}.TextRecord.{i}");
	USP_ARG_Add(kv, "Device.NAT.InterfaceSettingNumberOfEntries", "Device.NAT.InterfaceSetting.{i}");
	USP_ARG_Add(kv, "Device.NAT.PortMappingNumberOfEntries", "Device.NAT.PortMapping.{i}");
	USP_ARG_Add(kv, "Device.PCP.ClientNumberOfEntries", "Device.PCP.Client.{i}");
	USP_ARG_Add(kv, "Device.PCP.Client.{i}.ServerNumberOfEntries", "Device.PCP.Client.{i}.Server.{i}");
	USP_ARG_Add(kv, "Device.PCP.Client.{i}.Server.{i}.InboundMappingNumberOfEntries", "Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}");
	USP_ARG_Add(kv, "Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.FilterNumberOfEntries", "Device.PCP.Client.{i}.Server.{i}.InboundMapping.{i}.Filter.{i}");
	USP_ARG_Add(kv, "Device.PCP.Client.{i}.Server.{i}.OutboundMappingNumberOfEntries", "Device.PCP.Client.{i}.Server.{i}.OutboundMapping.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.ClientNumberOfEntries", "Device.DHCPv4.Client.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.Client.{i}.SentOptionNumberOfEntries", "Device.DHCPv4.Client.{i}.SentOption.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.Client.{i}.ReqOptionNumberOfEntries", "Device.DHCPv4.Client.{i}.ReqOption.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.Relay.ForwardingNumberOfEntries", "Device.DHCPv4.Relay.Forwarding.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.PoolNumberOfEntries", "Device.DHCPv4.Server.Pool.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.StaticAddressNumberOfEntries", "Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.OptionNumberOfEntries", "Device.DHCPv4.Server.Pool.{i}.Option.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.ClientNumberOfEntries", "Device.DHCPv4.Server.Pool.{i}.Client.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.Client.{i}.IPv4AddressNumberOfEntries", "Device.DHCPv4.Server.Pool.{i}.Client.{i}.IPv4Address.{i}");
	USP_ARG_Add(kv, "Device.DHCPv4.Server.Pool.{i}.Client.{i}.OptionNumberOfEntries", "Device.DHCPv4.Server.Pool.{i}.Client.{i}.Option.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.ClientNumberOfEntries", "Device.DHCPv6.Client.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.Client.{i}.ServerNumberOfEntries", "Device.DHCPv6.Client.{i}.Server.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.Client.{i}.SentOptionNumberOfEntries", "Device.DHCPv6.Client.{i}.SentOption.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.Client.{i}.ReceivedOptionNumberOfEntries", "Device.DHCPv6.Client.{i}.ReceivedOption.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.PoolNumberOfEntries", "Device.DHCPv6.Server.Pool.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.ClientNumberOfEntries", "Device.DHCPv6.Server.Pool.{i}.Client.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6AddressNumberOfEntries", "Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Address.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6PrefixNumberOfEntries", "Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Prefix.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.Client.{i}.OptionNumberOfEntries", "Device.DHCPv6.Server.Pool.{i}.Client.{i}.Option.{i}");
	USP_ARG_Add(kv, "Device.DHCPv6.Server.Pool.{i}.OptionNumberOfEntries", "Device.DHCPv6.Server.Pool.{i}.Option.{i}");
	USP_ARG_Add(kv, "Device.IEEE8021x.SupplicantNumberOfEntries", "Device.IEEE8021x.Supplicant.{i}");
	USP_ARG_Add(kv, "Device.Users.UserNumberOfEntries", "Device.Users.User.{i}");
	USP_ARG_Add(kv, "Device.SmartCardReaders.SmartCardReaderNumberOfEntries", "Device.SmartCardReaders.SmartCardReader.{i}");
	USP_ARG_Add(kv, "Device.UPnP.Discovery.RootDeviceNumberOfEntries", "Device.UPnP.Discovery.RootDevice.{i}");
	USP_ARG_Add(kv, "Device.UPnP.Discovery.DeviceNumberOfEntries", "Device.UPnP.Discovery.Device.{i}");
	USP_ARG_Add(kv, "Device.UPnP.Discovery.ServiceNumberOfEntries", "Device.UPnP.Discovery.Service.{i}");
	USP_ARG_Add(kv, "Device.UPnP.Description.DeviceDescriptionNumberOfEntries", "Device.UPnP.Description.DeviceDescription.{i}");
	USP_ARG_Add(kv, "Device.UPnP.Description.DeviceInstanceNumberOfEntries", "Device.UPnP.Description.DeviceInstance.{i}");
	USP_ARG_Add(kv, "Device.UPnP.Description.ServiceInstanceNumberOfEntries", "Device.UPnP.Description.ServiceInstance.{i}");
	USP_ARG_Add(kv, "Device.Firewall.LevelNumberOfEntries", "Device.Firewall.Level.{i}");
	USP_ARG_Add(kv, "Device.Firewall.ChainNumberOfEntries", "Device.Firewall.Chain.{i}");
	USP_ARG_Add(kv, "Device.Firewall.Chain.{i}.RuleNumberOfEntries", "Device.Firewall.Chain.{i}.Rule.{i}");
	USP_ARG_Add(kv, "Device.PeriodicStatistics.SampleSetNumberOfEntries", "Device.PeriodicStatistics.SampleSet.{i}");
	USP_ARG_Add(kv, "Device.PeriodicStatistics.SampleSet.{i}.ParameterNumberOfEntries", "Device.PeriodicStatistics.SampleSet.{i}.Parameter.{i}");
	USP_ARG_Add(kv, "Device.FaultMgmt.SupportedAlarmNumberOfEntries", "Device.FaultMgmt.SupportedAlarm.{i}");
	USP_ARG_Add(kv, "Device.FaultMgmt.CurrentAlarmNumberOfEntries", "Device.FaultMgmt.CurrentAlarm.{i}");
	USP_ARG_Add(kv, "Device.FaultMgmt.HistoryEventNumberOfEntries", "Device.FaultMgmt.HistoryEvent.{i}");
	USP_ARG_Add(kv, "Device.FaultMgmt.ExpeditedEventNumberOfEntries", "Device.FaultMgmt.ExpeditedEvent.{i}");
	USP_ARG_Add(kv, "Device.FaultMgmt.QueuedEventNumberOfEntries", "Device.FaultMgmt.QueuedEvent.{i}");
	USP_ARG_Add(kv, "Device.FAP.PerfMgmt.ConfigNumberOfEntries", "Device.FAP.PerfMgmt.Config.{i}");
	USP_ARG_Add(kv, "Device.XMPP.ConnectionNumberOfEntries", "Device.XMPP.Connection.{i}");
	USP_ARG_Add(kv, "Device.XMPP.Connection.{i}.ServerNumberOfEntries", "Device.XMPP.Connection.{i}.Server.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.InterfaceNumberOfEntries", "Device.IEEE1905.AL.Interface.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.Interface.{i}.VendorPropertiesNumberOfEntries", "Device.IEEE1905.AL.Interface.{i}.VendorProperties.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.Interface.{i}.LinkNumberOfEntries", "Device.IEEE1905.AL.Interface.{i}.Link.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.ForwardingTable.ForwardingRuleNumberOfEntries", "Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.ChangeLogNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.ChangeLog.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905DeviceNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4AddressNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6AddressNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorPropertiesNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorProperties.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.InterfaceNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905NeighborNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.L2NeighborNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.L2Neighbor.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905NeighborNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.MetricNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}");
	USP_ARG_Add(kv, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTupleNumberOfEntries", "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}");
	USP_ARG_Add(kv, "Device.DynamicDNS.ClientNumberOfEntries", "Device.DynamicDNS.Client.{i}");
	USP_ARG_Add(kv, "Device.DynamicDNS.Client.{i}.HostnameNumberOfEntries", "Device.DynamicDNS.Client.{i}.Hostname.{i}");
	USP_ARG_Add(kv, "Device.DynamicDNS.ServerNumberOfEntries", "Device.DynamicDNS.Server.{i}");
	USP_ARG_Add(kv, "Device.LEDs.LEDNumberOfEntries", "Device.LEDs.LED.{i}");
	USP_ARG_Add(kv, "Device.LEDs.LED.{i}.CycleElementNumberOfEntries", "Device.LEDs.LED.{i}.CycleElement.{i}");
	USP_ARG_Add(kv, "Device.BASAPM.MeasurementEndpointNumberOfEntries", "Device.BASAPM.MeasurementEndpoint.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgentNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.TaskCapabilityNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.TaskCapability.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.TaskCapability.{i}.TaskCapabilityRegistryNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.TaskCapability.{i}.Registry.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.ScheduleNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.Schedule.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Schedule.{i}.ActionNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.Schedule.{i}.Action.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Schedule.{i}.Action.{i}.OptionNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.Schedule.{i}.Action.{i}.Option.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.TaskNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.Task.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Task.{i}.RegistryNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.Task.{i}.Registry.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Task.{i}.OptionNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.Task.{i}.Option.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.CommunicationChannelNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.CommunicationChannel.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.InstructionNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.Instruction.{i}");
	USP_ARG_Add(kv, "Device.LMAP.MeasurementAgent.{i}.Instruction.{i}.MeasurementSuppressionNumberOfEntries", "Device.LMAP.MeasurementAgent.{i}.Instruction.{i}.MeasurementSuppression.{i}");
	USP_ARG_Add(kv, "Device.LMAP.ReportNumberOfEntries", "Device.LMAP.Report.{i}");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.ResultNumberOfEntries", "Device.LMAP.Report.{i}.Result.{i}");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.Result.{i}.OptionNumberOfEntries", "Device.LMAP.Report.{i}.Result.{i}.Option.{i}");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.Result.{i}.ResultConflictNumberOfEntries", "Device.LMAP.Report.{i}.Result.{i}.Conflict.{i}");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.Result.{i}.ResultReportTableNumberOfEntries", "Device.LMAP.Report.{i}.Result.{i}.ReportTable.{i}");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.Result.{i}.ReportTable.{i}.ResultReportRowNumberOfEntries", "Device.LMAP.Report.{i}.Result.{i}.ReportTable.{i}.ResultRow.{i}");
	USP_ARG_Add(kv, "Device.LMAP.Report.{i}.Result.{i}.ReportTable.{i}.RegistryNumberOfEntries", "Device.LMAP.Report.{i}.Result.{i}.ReportTable.{i}.Registry.{i}");
	USP_ARG_Add(kv, "Device.LMAP.EventNumberOfEntries", "Device.LMAP.Event.{i}");
	USP_ARG_Add(kv, "Device.SoftwareModules.ExecEnvNumberOfEntries", "Device.SoftwareModules.ExecEnv.{i}");
	USP_ARG_Add(kv, "Device.SoftwareModules.DeploymentUnitNumberOfEntries", "Device.SoftwareModules.DeploymentUnit.{i}");
	USP_ARG_Add(kv, "Device.SoftwareModules.ExecutionUnitNumberOfEntries", "Device.SoftwareModules.ExecutionUnit.{i}");
	USP_ARG_Add(kv, "Device.ProxiedDeviceNumberOfEntries", "Device.ProxiedDevice.{i}");
	USP_ARG_Add(kv, "Device.ProxiedDevice.{i}.NodeNumberOfEntries", "Device.ProxiedDevice.{i}.Node.{i}");
	USP_ARG_Add(kv, "Device.IoTCapabilityNumberOfEntries", "Device.IoTCapability.{i}");

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
			break;
		}

		parameter = json_find_member(member, "parameter");
		value = json_find_member(member, "value");
		if (parameter == NULL || value == NULL) {
			break;
		}

		if (parameter->tag == JSON_STRING &&
		    value->tag == JSON_STRING) {
			USP_ARG_Add(kv_out, parameter->string_, value->string_);
		}
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
			break;
		}
	}
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
				break;
			}
		}
	}
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

int uspd_operate_sync(dm_req_t *req, __unused char *command_key, kv_vector_t *input_args, kv_vector_t *output_args)
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
	}
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
			continue;
		}

		if (parameter->tag == JSON_STRING &&
		    value->tag == JSON_STRING) {
			USP_ARG_Add(kv, parameter->string_, value->string_);
		}
	}
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

static void schema_get_cb(struct ubus_request *req, __unused int type, struct blob_attr *msg)
{
	JsonNode *json, *parameters, *member;
	kv_vector_t *kv;
	char *str;

	if (!msg) {
		USP_LOG_Error("[%s:%d] recieved msg is null",__func__, __LINE__);
		return;
	}

	kv = (kv_vector_t *) req->priv;

	str = (char *) blobmsg_format_json_indent(msg, true, -1);
	if (str == NULL) {
		return;
	}

	json = json_decode(str);
	if (json == NULL) {
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
		JsonNode *parameter, *write, *type;

		parameter = json_find_member(member, "parameter");
		write = json_find_member(member, "writable");
		type = json_find_member(member, "type");

		if (parameter == NULL || write == NULL || type == NULL) {
			continue;
		}

		if (parameter->tag == JSON_STRING &&
		    write->tag == JSON_STRING &&
		    type->tag == JSON_STRING) {
			size_t slen;
			char spath[MAX_DM_PATH] = { 0 };
			char val[MAX_DM_PATH] = { 0 };
			get_schema_path(parameter->string_, spath);
			slen = strlen(spath);
			if (spath[slen - 1] == '.' && spath[slen - 2] != '}')
				continue;

			if (spath[slen - 1] == '.')
				spath[slen - 1] = '\0';

			if (USP_ARG_Get(kv, spath, NULL) == NULL) {
				USP_SNPRINTF(val, MAX_DM_PATH, "%s %s", type->string_, write->string_);
				USP_ARG_Add(kv, spath, val);
			}
		}
	}
	json_delete(parameters);
	json_delete(json);
	USP_SAFE_FREE(str);
}

int uspd_get_object_paths(kv_vector_t *kv)
{
	int fault = USP_ERR_OK;
	struct blob_buf b = { };

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "path", "Device.");
	blobmsg_add_string(&b, "proto", "usp");
	blobmsg_add_u8(&b, "next-level", false);

	// Invoke Ubus to get data from uspd
	fault = uspd_call("object_names", &b, schema_get_cb, kv);

	blob_buf_free(&b);
	return fault;
}

bool is_alias(char *path)
{
	char *p;
	if (path == NULL)
		return false;

	size_t slen = strlen(path);
	if (slen < 7)
		return false;

	p = &path[slen - 6];
	if (strncmp(p, ".Alias", 6) == 0)
		return true;

	return false;
}
int uspd_set_value(dm_req_t *req, char *buf)
{
	int fault = 0;
	USP_LOG_Error("set called path(%s), value(%s)", req->path, buf);
	uspd_set_path_value(req->path, buf, &fault);

	return fault;
}

int uspd_get_value(dm_req_t *req, char *buf, int len)
{
	char *val;
	struct vendor_get_param vget;

	vendor_get_arg_init(&vget);
	kv_vector_t *kv_vec = &vget.kv_vec;

	uspd_get_path_value(req->path, &vget);
	val = USP_ARG_Get(kv_vec, req->path, NULL);
	if (val)
		strncpy(buf, val, len);

	USP_ARG_Destroy(kv_vec);

	return vget.fault;
}

int uspd_add_dummy(dm_req_t *req)
{
	struct vendor_add_arg vadd = {USP_ERR_OK, 0};

        uspd_add_object(req->path, &vadd);

	return vadd.fault;
}

int uspd_add_notify(dm_req_t *req)
{
	int err = USP_ERR_OK;
	dm_req_t alias_dm;
	char path[MAX_DM_PATH] = {0};
	char value[MAX_DM_VALUE_LEN] = {0};

	USP_SNPRINTF(path, MAX_DM_PATH, "%s.Alias", req->path);
	alias_dm.path = path;

	err = uspd_get_value(&alias_dm, value, MAX_DM_VALUE_LEN);
	if (err == USP_ERR_OK) {
		err = DATA_MODEL_SetParameterInDatabase(path, value);
	}
	return err;
}

int uspd_del_dummy(dm_req_t *req)
{
	return uspd_del_object(req->path);
}

static void uspd_register_uniq_param(char *spath, kv_vector_t *kv)
{
	int i;
	int key_count = 0;
	char **unique_keys = NULL, *temp_val;
	char *tok, *save;

	temp_val = USP_STRDUP(USP_ARG_Get(kv, spath, "Alias"));

	tok = strtok_r(temp_val, ";", &save);
	while (tok != NULL) {
		if (key_count == 0) {
			unique_keys = USP_MALLOC(sizeof(char *));
		} else {
			unique_keys = USP_REALLOC(unique_keys, sizeof(char *) * key_count);
		}
		unique_keys[key_count] = USP_STRDUP(tok);
		key_count++;
		tok = strtok_r(NULL, ";", &save);
	}
	USP_SAFE_FREE(temp_val);

	if (key_count)
		USP_REGISTER_Object_UniqueKey(spath, unique_keys, key_count);

	for (i = 0; i < key_count; i++) {
		USP_SAFE_FREE(unique_keys[i]);
	}
	USP_SAFE_FREE(unique_keys);
}

static void uspd_register_object(char *spath)
{
	char alias[MAX_DM_PATH] = {0};

	USP_REGISTER_Object(spath, NULL, uspd_add_dummy, uspd_add_notify, NULL, uspd_del_dummy, NULL);

	// register alias
	strcpy(alias, spath);
	strcat(alias, ".Alias");
	USP_REGISTER_DBParam_Alias(alias, NULL);
}

int get_dm_type(char *type)
{
	if (strcmp(type, "xsd:string") == 0)
		return DM_STRING;
	else if(strcmp(type, "xsd:unsignedInt") == 0)
		return DM_UINT;
	else if (strcmp(type, "xsd:int") == 0)
		return DM_INT;
	else if (strcmp(type, "xsd:unsignedLong") == 0)
		return DM_ULONG;
	else if (strcmp(type, "xsd:Long") == 0)
		return DM_ULONG;
	else if (strcmp(type, "xsd:boolean") == 0)
		return DM_BOOL;
	else if (strcmp(type, "xsd:dateTime") == 0)
		return DM_DATETIME;
	else
		return DM_STRING;

	return DM_STRING;
}

bool is_num_entries(kv_vector_t *kv, char *path)
{
	char *value;

	value = USP_ARG_Get(kv, path, NULL);

	if (value) {
		USP_REGISTER_Param_NumEntries(path, value);
		return true;
	}
	return false;
}

void uspd_register_leaf(char *spath, char *permstr, char *dmtype)
{
	bool rw_perm = false;
	int type = get_dm_type(dmtype);

	if (TEXT_UTILS_StringToBool(permstr, &rw_perm) != USP_ERR_OK) {
		return;
	}

	if (rw_perm) {
		USP_REGISTER_VendorParam_ReadWrite(spath, uspd_get_value, uspd_set_value, NULL, type);
	} else {
		USP_REGISTER_VendorParam_ReadOnly(spath, uspd_get_value, type);
	}
}

bool register_uspd_schema(kv_vector_t *kv)
{
	int i;
	char *spath;
	kv_vector_t kv_num_entries;


	USP_ARG_Init(&kv_num_entries);
	vendor_num_entries_init(&kv_num_entries);

	for (i = 0; i < kv->num_entries; ++i) {
		char *type;
		char *write;
		spath = kv->vector[i].key;

		TEXT_UTILS_KeyValueFromString(kv->vector[i].value, &type, &write);
		// register object
		if (strncmp(type, "xsd:object", 10) == 0) {
			uspd_register_object(spath);
			continue;
		}
		if (is_alias(spath))
			continue;

		if (is_num_entries(&kv_num_entries, spath))
			continue;

		uspd_register_leaf(spath, write, type);
	}

	kv_vector_t uniq_kv;

	USP_ARG_Init(&uniq_kv);
	vendor_uniq_key_init(&uniq_kv);

	for (i = 0; i < kv->num_entries; ++i) {
		spath = kv->vector[i].key;
		// register object
		if (strncmp(kv->vector[i].value, "xsd:object", 10) == 0) {
			uspd_register_uniq_param(spath, &uniq_kv);
		}
	}

	USP_ARG_Destroy(&uniq_kv);
	USP_ARG_Destroy(&kv_num_entries);
	return true;
}

void uspd_register_schema()
{
	kv_vector_t kv_vec;

	USP_ARG_Init(&kv_vec);

	uspd_get_object_paths(&kv_vec);
	register_uspd_schema(&kv_vec);
	USP_ARG_Destroy(&kv_vec);
}

static int dm_instance_init(void)
{
	int i;
	str_vector_t instance_vector;
	STR_VECTOR_Init(&instance_vector);

	uspd_get_instances("Device.", &instance_vector);

	for(i=0; i< instance_vector.num_entries; ++i) {
		USP_DM_InformInstance(instance_vector.vector[i]);
	}

	STR_VECTOR_Clone(&g_inst_vector, instance_vector.vector,
			 instance_vector.num_entries);

	STR_VECTOR_Destroy(&instance_vector);
	return USP_ERR_OK;
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

void *monitor_instances(void *arg __unused) {
	while(FOREVER) {
		sleep(INST_MONITOR_TIMER);
		int i = 0, j = 0;
		str_vector_t inst_vect;
		STR_VECTOR_Init(&inst_vect);

		uspd_get_instances("Device.", &inst_vect);

		while((i < inst_vect.num_entries) && (j < g_inst_vector.num_entries)) {
			if(!strcmp(inst_vect.vector[i], g_inst_vector.vector[j])) {
				i++; j++;
				continue;
			} else if(strcmp(inst_vect.vector[i], g_inst_vector.vector[j]) < 0) {
				// need to add current vector node
				USP_LOG_Debug("Object Instance Added:|%s|", inst_vect.vector[i]);
				USP_SIGNAL_ObjectAdded(inst_vect.vector[i]);
				i++;
			} else if(strcmp(inst_vect.vector[i], g_inst_vector.vector[j]) > 0) {
				//need to delete previous vector node
				USP_LOG_Debug("Object Instance Deleted:|%s|", g_inst_vector.vector[j]);
				USP_SIGNAL_ObjectDeleted(g_inst_vector.vector[j]);
				j++;
			}
		}

		// Delete all the remaining nodes from old instance
		while(j < g_inst_vector.num_entries) {
			USP_LOG_Debug("Object Instance Deleted:|%s|", g_inst_vector.vector[j]);
			USP_SIGNAL_ObjectDeleted(g_inst_vector.vector[j]);
			j++;
		}

		// Add all the remaining nodes from current instances
		while(i < inst_vect.num_entries) {
			USP_LOG_Debug("Object Instance Added:|%s|", inst_vect.vector[i]);
			USP_SIGNAL_ObjectAdded(inst_vect.vector[i]);
			i++;
		}

		STR_VECTOR_Destroy(&g_inst_vector);
		STR_VECTOR_Clone(&g_inst_vector, inst_vect.vector, inst_vect.num_entries);
		STR_VECTOR_Destroy(&inst_vect);
	}
	return NULL;
}

int vendor_uspd_init()
{
	uspd_register_schema();
	vendor_operate_sync_init();
	vendor_operate_async_init();
	vendor_factory_reset_init();
	vendor_reset_init();

	if (is_running_cli_local_command == false)
	{
		dm_instance_init();
	}

	return USP_ERR_OK;
}

int vendor_uspd_stop()
{
	STR_VECTOR_Destroy(&gs_async_paths);
	STR_VECTOR_Destroy(&g_inst_vector);
	return USP_ERR_OK;
}


int vendor_uspd_start()
{
	// Start a thread to monitor datamodel instances
	OS_UTILS_CreateThread(monitor_instances, NULL);
	return USP_ERR_OK;
}
