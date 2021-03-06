/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.t3.cli;

import com.google.common.base.Preconditions;
import com.google.common.primitives.UnsignedLongs;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.TpPort;
import org.onlab.packet.VlanId;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.PlaceholderCompleter;
import org.onosproject.cli.net.ConnectPointCompleter;
import org.onosproject.cli.net.EthTypeCompleter;
import org.onosproject.cli.net.IpProtocolCompleter;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.t3.api.StaticPacketTrace;
import org.onosproject.t3.api.TroubleshootService;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.onlab.packet.EthType.EtherType;

/**
 * Starts a Static Packet Trace for a given input and prints the result.
 */
@Service
@Command(scope = "onos", name = "t3-troubleshoot",
        description = "troubleshoots flows and groups between source and destination")
public class TroubleshootTraceCommand extends AbstractShellCommand {

    private static final Pattern NAMED = Pattern.compile("^(?<deviceid>\\S*)\\/\\[(?<name>\\S*)\\]\\((?<num>\\d+)\\)$");

    private static final Pattern NOT_NAMED = Pattern.compile("^(?<deviceid>\\S*)\\/(?<num>\\d+)$");

    private static final String FLOW_SHORT_FORMAT = "    %s, bytes=%s, packets=%s, "
            + "table=%s, priority=%s, selector=%s, treatment=%s";

    private static final String GROUP_FORMAT =
            "   id=0x%s, state=%s, type=%s, bytes=%s, packets=%s, appId=%s, referenceCount=%s";
    private static final String GROUP_BUCKET_FORMAT =
            "       id=0x%s, bucket=%s, bytes=%s, packets=%s, actions=%s";

    private static final String CONTROLLER = "CONTROLLER";

    @Option(name = "-v", aliases = "--verbose", description = "Outputs complete path")
    @Completion(PlaceholderCompleter.class)
    private boolean verbosity1 = false;

    @Option(name = "-vv", aliases = "--veryverbose", description = "Outputs flows and groups for every device")
    @Completion(PlaceholderCompleter.class)
    private boolean verbosity2 = false;

    @Option(name = "-s", aliases = "--srcIp", description = "Source IP")
    @Completion(PlaceholderCompleter.class)
    String srcIp = null;

    @Option(name = "-sp", aliases = "--srcPort", description = "Source Port", required = true)
    @Completion(ConnectPointCompleter.class)
    String srcPort = null;

    @Option(name = "-sm", aliases = "--srcMac", description = "Source MAC")
    @Completion(PlaceholderCompleter.class)
    String srcMac = null;

    @Option(name = "-et", aliases = "--ethType", description = "ETH Type", valueToShowInHelp = "ipv4")
    @Completion(EthTypeCompleter.class)
    String ethType = "ipv4";

    @Option(name = "-stp", aliases = "--srcTcpPort", description = "Source TCP Port")
    @Completion(PlaceholderCompleter.class)
    String srcTcpPort = null;

    @Option(name = "-d", aliases = "--dstIp", description = "Destination IP")
    @Completion(PlaceholderCompleter.class)
    String dstIp = null;

    @Option(name = "-dm", aliases = "--dstMac", description = "Destination MAC")
    @Completion(PlaceholderCompleter.class)
    String dstMac = null;

    @Option(name = "-dtp", aliases = "--dstTcpPort", description = "destination TCP Port")
    @Completion(PlaceholderCompleter.class)
    String dstTcpPort = null;

    @Option(name = "-vid", aliases = "--vlanId", description = "Vlan of incoming packet", valueToShowInHelp = "None")
    @Completion(PlaceholderCompleter.class)
    String vlan = "None";

    @Option(name = "-ml", aliases = "--mplsLabel", description = "Mpls label of incoming packet")
    @Completion(PlaceholderCompleter.class)
    String mplsLabel = null;

    @Option(name = "-mb", aliases = "--mplsBos", description = "MPLS BOS")
    @Completion(PlaceholderCompleter.class)
    String mplsBos = null;

    @Option(name = "-ipp", aliases = "--ipProto", description = "IP Proto")
    @Completion(IpProtocolCompleter.class)
    String ipProto = null;

    @Option(name = "-udps", aliases = "--udpSrc", description = "UDP Source")
    @Completion(PlaceholderCompleter.class)
    String udpSrc = null;

    @Option(name = "-udpd", aliases = "--udpDst", description = "UDP Destination")
    @Completion(PlaceholderCompleter.class)
    String udpDst = null;

    @Override
    protected void doExecute() {
        TroubleshootService service = get(TroubleshootService.class);
        if (!service.checkNibValidity()) {
            // if the NIB is found invalid, fill it with the current network states so that this command can proceed
            print(T3CliUtils.NIB_AUTOFILLED);
            TroubleshootLoadSnapshotCommand cmd = new TroubleshootLoadSnapshotCommand();
            cmd.doExecute();
            if (!service.checkNibValidity()) {
                // if the NIB is still invalid even after auto-filled snapshots, stop and warn
                print(T3CliUtils.NIB_TERMINATE);
                return;
            }
        } else {
            print(service.printNibSummary());
        }

        // Uses input port as a convenience to carry the Controller port, proper flood behaviour is handled in the
        // troubleshoot manager.
        ConnectPoint cp = parseConnectPoint(srcPort);
        EtherType type = EtherType.valueOf(ethType.toUpperCase());

        //Input Port must be specified
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchInPort(cp.port());

        if (srcIp != null) {
            if (type.equals(EtherType.IPV6)) {
                selectorBuilder.matchIPv6Src(IpAddress.valueOf(srcIp).toIpPrefix());
            } else {
                selectorBuilder.matchIPSrc(IpAddress.valueOf(srcIp).toIpPrefix());
            }
        }

        if (srcMac != null) {
            selectorBuilder.matchEthSrc(MacAddress.valueOf(srcMac));
        }

        //if EthType option is not specified using IPv4
        selectorBuilder.matchEthType(type.ethType().toShort());

        if (srcTcpPort != null) {
            selectorBuilder.matchTcpSrc(TpPort.tpPort(Integer.parseInt(srcTcpPort)));
        }

        if (dstIp != null) {
            if (type.equals(EtherType.IPV6)) {
                selectorBuilder.matchIPv6Dst(IpAddress.valueOf(dstIp).toIpPrefix());
            } else {
                selectorBuilder.matchIPDst(IpAddress.valueOf(dstIp).toIpPrefix());
            }
        }

        if (dstMac != null) {
            selectorBuilder.matchEthDst(MacAddress.valueOf(dstMac));
        }
        if (dstTcpPort != null) {
            selectorBuilder.matchTcpDst(TpPort.tpPort(Integer.parseInt(dstTcpPort)));
        }

        //if vlan option is not specified using NONE
        selectorBuilder.matchVlanId(VlanId.vlanId(vlan));

        if (mplsLabel != null) {
            selectorBuilder.matchMplsLabel(MplsLabel.mplsLabel(Integer.parseInt(mplsLabel)));
        }

        if (mplsBos != null) {
            selectorBuilder.matchMplsBos(Boolean.valueOf(mplsBos));
        }

        if (ipProto != null) {
            selectorBuilder.matchIPProtocol(Byte.valueOf(ipProto));
        }

        if (udpSrc != null) {
            selectorBuilder.matchUdpSrc(TpPort.tpPort(Integer.parseInt(udpSrc)));
        }

        if (udpDst != null) {
            selectorBuilder.matchUdpDst(TpPort.tpPort(Integer.parseInt(udpDst)));
        }


        TrafficSelector packet = selectorBuilder.build();

        //Printing the created packet
        print("Tracing packet: %s", packet.criteria());

        //Build the trace
        StaticPacketTrace trace = service.trace(packet, cp);

        print("%s", T3CliUtils.printTrace(trace, verbosity1, verbosity2));

    }

    private ConnectPoint parseConnectPoint(String cp) {
        String deviceId;
        String name;
        String num;

        Matcher matcher = NAMED.matcher(cp);
        // If it is not a named port - try to parse using classic way
        if (!matcher.matches()) {
            matcher = NOT_NAMED.matcher(cp);
            Preconditions.checkArgument(matcher.matches(), "wrong format of source port");
            deviceId = matcher.group("deviceid");
            num = matcher.group("num");
            return new ConnectPoint(DeviceId.deviceId(deviceId),
                    PortNumber.portNumber(num));
        }
        // Named port - decomposes in sub components
        deviceId = matcher.group("deviceid");
        name = matcher.group("name");
        num = matcher.group("num");
        return new ConnectPoint(DeviceId.deviceId(deviceId),
                PortNumber.portNumber(UnsignedLongs.parseUnsignedLong(num), name));
    }
}
