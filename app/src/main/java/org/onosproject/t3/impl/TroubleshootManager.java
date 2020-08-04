/*
 * Copyright 2017-present Open Networking Foundation
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

package org.onosproject.t3.impl;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.collect.Maps;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.onlab.packet.IpAddress;
import org.onlab.packet.VlanId;
import org.onlab.util.Generator;
import org.onosproject.cluster.NodeId;

import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.PipelineTraceableHitChain;
import org.onosproject.net.PipelineTraceableInput;
import org.onosproject.net.PipelineTraceableOutput;
import org.onosproject.net.PipelineTraceableOutput.PipelineTraceableResult;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.PipelineTraceable;
import org.onosproject.net.config.ConfigException;
import org.onosproject.net.config.basics.InterfaceConfig;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.EthTypeCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.group.Group;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.intf.Interface;
import org.onosproject.routeservice.ResolvedRoute;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.onosproject.t3.api.DeviceNib;
import org.onosproject.t3.api.DriverNib;
import org.onosproject.t3.api.EdgePortNib;
import org.onosproject.t3.api.FlowNib;
import org.onosproject.t3.api.GroupNib;
import org.onosproject.t3.api.HostNib;
import org.onosproject.t3.api.LinkNib;
import org.onosproject.t3.api.MastershipNib;
import org.onosproject.t3.api.MulticastRouteNib;
import org.onosproject.t3.api.NetworkConfigNib;
import org.onosproject.t3.api.NibProfile;
import org.onosproject.t3.api.RouteNib;
import org.onosproject.t3.api.StaticPacketTrace;
import org.onosproject.t3.api.TroubleshootService;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;

import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Optional;
import java.util.ArrayList;
import java.util.Collections;

import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.onlab.packet.EthType.EtherType;
import static org.onosproject.net.flow.TrafficSelector.Builder;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Manager to troubleshoot packets inside the network.
 * Given a representation of a packet follows it's path in the network according to the existing flows and groups in
 * the devices.
 */
@Component(immediate = true, service = TroubleshootService.class)
public class TroubleshootManager implements TroubleshootService {

    private static final Logger log = getLogger(TroubleshootManager.class);

    static final String PACKET_TO_CONTROLLER = "Packet goes to the controller";

    // uses a snapshot (cache) of NIBs instead of interacting with ONOS core in runtime
    protected FlowNib flowNib = FlowNib.getInstance();
    protected GroupNib groupNib = GroupNib.getInstance();
    protected LinkNib linkNib = LinkNib.getInstance();
    protected HostNib hostNib = HostNib.getInstance();
    protected DeviceNib deviceNib = DeviceNib.getInstance();
    protected DriverNib driverNib = DriverNib.getInstance();
    protected MastershipNib mastershipNib = MastershipNib.getInstance();
    protected EdgePortNib edgePortNib = EdgePortNib.getInstance();
    protected RouteNib routeNib = RouteNib.getInstance();
    protected NetworkConfigNib networkConfigNib = NetworkConfigNib.getInstance();
    protected MulticastRouteNib mcastRouteNib = MulticastRouteNib.getInstance();

    // FIXME Revisit offline mode after a first implementation
    private final Map<DeviceId, PipelineTraceable> pipelineTraceables = Maps.newConcurrentMap();

    @Override
    public boolean checkNibValidity() {
        return Stream.of(flowNib, groupNib, linkNib, hostNib, deviceNib, driverNib,
                mastershipNib, edgePortNib, routeNib, networkConfigNib, mcastRouteNib)
                .allMatch(nib -> nib != null && nib.isValid());
    }

    @Override
    public String printNibSummary() {
        StringBuilder summary = new StringBuilder().append("*** Current NIB in valid: ***\n");
        Stream.of(flowNib, groupNib, linkNib, hostNib, deviceNib, driverNib,
                mastershipNib, edgePortNib, routeNib, networkConfigNib, mcastRouteNib)
                .forEach(nib -> {
                    NibProfile profile = nib.getProfile();
                    summary.append(String.format(
                            nib.getClass().getName() + " created %s from %s\n",
                            profile.date(), profile.sourceType()));
                });

        return summary.append(StringUtils.rightPad("", 125, '-')).toString();
    }

    @Override
    public Generator<Set<StaticPacketTrace>> pingAllGenerator(EtherType type) {
        return new PingAllGenerator(type, hostNib, this);
    }

    @Override
    public Generator<Set<StaticPacketTrace>> traceMcast(VlanId vlanId) {
        return new McastGenerator(mcastRouteNib, this, vlanId);
    }

    @Override
    public Set<StaticPacketTrace> trace(HostId sourceHost, HostId destinationHost, EtherType etherType) {
        Host source = hostNib.getHost(sourceHost);
        Host destination = hostNib.getHost(destinationHost);

        //Temporary trace to fail in case we don't have enough information or what is provided is incoherent
        StaticPacketTrace failTrace = new StaticPacketTrace(null, null, Pair.of(source, destination));

        if (source == null) {
            failTrace.addResultMessage("Source Host " + sourceHost + " does not exist");
            failTrace.setSuccess(false);

            return ImmutableSet.of(failTrace);
        }

        if (destination == null) {
            failTrace.addResultMessage("Destination Host " + destinationHost + " does not exist");
            failTrace.setSuccess(false);
            return ImmutableSet.of(failTrace);
        }

        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchEthType(etherType.ethType().toShort())
                .matchEthDst(source.mac())
                .matchVlanId(source.vlan());


        try {
            ImmutableSet.Builder<StaticPacketTrace> traces = ImmutableSet.builder();
            //if the location deviceId is the same, the two hosts are under same subnet and vlan on the interface
            // we are under same leaf so it's L2 Unicast.
            if (areBridged(source, destination)) {
                selectorBuilder.matchEthDst(destination.mac());
                source.locations().forEach(hostLocation -> {
                    selectorBuilder.matchInPort(hostLocation.port());
                    StaticPacketTrace trace = trace(selectorBuilder.build(), hostLocation);
                    trace.addEndpointHosts(Pair.of(source, destination));
                    traces.add(trace);
                });
                //The destination host is not dual homed, if it is the other path might be done through routing.
                if (destination.locations().size() == 1) {
                    return traces.build();
                }
            }
            //handle the IPs for src and dst in case of L3
            if (etherType.equals(EtherType.IPV4) || etherType.equals(EtherType.IPV6)) {

                //Match on the source IP
                if (!matchIP(source, failTrace, selectorBuilder, etherType, true)) {
                    return ImmutableSet.of(failTrace);
                }

                //Match on destination IP
                if (!matchIP(destination, failTrace, selectorBuilder, etherType, false)) {
                    return ImmutableSet.of(failTrace);
                }

            } else {
                failTrace.addResultMessage("Host based trace supports only IPv4 or IPv6 as EtherType, " +
                        "please use packet based");
                failTrace.setSuccess(false);
                return ImmutableSet.of(failTrace);
            }

            //l3 unicast, we get the dst mac of the leaf the source is connected to from netcfg
            SegmentRoutingDeviceConfig segmentRoutingConfig = networkConfigNib.getConfig(source.location()
                    .deviceId(), SegmentRoutingDeviceConfig.class);
            if (segmentRoutingConfig != null) {
                selectorBuilder.matchEthDst(segmentRoutingConfig.routerMac());
            } else {
                failTrace.addResultMessage("Can't get " + source.location().deviceId() +
                        " router MAC from segment routing config can't perform L3 tracing.");
                failTrace.setSuccess(false);
            }
            source.locations().forEach(hostLocation -> {
                selectorBuilder.matchInPort(hostLocation.port());
                StaticPacketTrace trace = trace(selectorBuilder.build(), hostLocation);
                trace.addEndpointHosts(Pair.of(source, destination));
                traces.add(trace);
            });
            return traces.build();

        } catch (ConfigException e) {
            failTrace.addResultMessage("Can't get config " + e.getMessage());
            return ImmutableSet.of(failTrace);
        }
    }

    private PipelineTraceable getPipelineMatchable(DeviceId deviceId) {
        return pipelineTraceables.compute(deviceId, (k, v) -> {
            if (v == null) {
                log.info("PipelineMatchable not found for {}", deviceId);
                Device d = deviceNib.getDevice(deviceId);
                if (d.is(PipelineTraceable.class)) {
                    v = d.as(PipelineTraceable.class);
                    v.init();
                } else {
                    log.warn("PipelineMatchable behaviour not supported for device {}",
                            deviceId);
                }
            }
            return v;
        });
    }

    private List<DataPlaneEntity> getDataPlaneEntities(DeviceId deviceId) {
        List<DataPlaneEntity> dataPlaneEntities = Lists.newArrayList();
        flowNib.getFlowEntriesByState(deviceId, FlowEntry.FlowEntryState.ADDED).forEach(entity ->
                dataPlaneEntities.add(new DataPlaneEntity(entity)));
        groupNib.getGroupsByState(deviceId, Group.GroupState.ADDED).forEach(entity ->
                dataPlaneEntities.add(new DataPlaneEntity(entity)));
        return dataPlaneEntities;
    }

    /**
     * Matches src and dst IPs based on host information.
     *
     * @param host            the host
     * @param failTrace       the trace to use in case of failure
     * @param selectorBuilder the packet we are building to trace
     * @param etherType       the traffic type
     * @param src             is this src host or dst host
     * @return true if properly matched
     */
    private boolean matchIP(Host host, StaticPacketTrace failTrace, Builder selectorBuilder,
                            EtherType etherType, boolean src) {
        List<IpAddress> ips = getIpAddresses(host, etherType, true);

        if (ips.size() > 0) {
            if (etherType.equals(EtherType.IPV4)) {
                if (src) {
                    selectorBuilder.matchIPSrc(ips.get(0).toIpPrefix());
                } else {
                    selectorBuilder.matchIPDst(ips.get(0).toIpPrefix());
                }
            } else if (etherType.equals(EtherType.IPV6)) {
                if (src) {
                    selectorBuilder.matchIPv6Src(ips.get(0).toIpPrefix());
                } else {
                    selectorBuilder.matchIPv6Dst(ips.get(0).toIpPrefix());
                }
            }
        } else {
            failTrace.addResultMessage("Host " + host + " has no " + etherType + " address");
            failTrace.setSuccess(false);
            return false;
        }
        return true;
    }

    List<IpAddress> getIpAddresses(Host host, EtherType etherType, boolean checklocal) {
        return host.ipAddresses().stream().filter(ipAddress -> {
            boolean correctIp = false;
            if (etherType.equals(EtherType.IPV4)) {
                correctIp = ipAddress.isIp4();
            } else if (etherType.equals(EtherType.IPV6)) {
                correctIp = ipAddress.isIp6();
            }
            if (checklocal) {
                correctIp = correctIp && !ipAddress.isLinkLocal();
            }
            return correctIp;
        }).collect(Collectors.toList());
    }

    /**
     * Checks that two hosts are bridged (L2Unicast).
     *
     * @param source      the source host
     * @param destination the destination host
     * @return true if bridged.
     * @throws ConfigException if config can't be properly retrieved
     */
    private boolean areBridged(Host source, Host destination) throws ConfigException {

        //If the locations is not the same we don't even check vlan or subnets
        if (Collections.disjoint(source.locations(), destination.locations())) {
            return false;
        }

        if (!source.vlan().equals(VlanId.NONE) && !destination.vlan().equals(VlanId.NONE)
                && !source.vlan().equals(destination.vlan())) {
            return false;
        }

        InterfaceConfig interfaceCfgH1 = networkConfigNib.getConfig(source.location(), InterfaceConfig.class);
        InterfaceConfig interfaceCfgH2 = networkConfigNib.getConfig(destination.location(), InterfaceConfig.class);
        if (interfaceCfgH1 != null && interfaceCfgH2 != null) {

            //following can be optimized but for clarity is left as is
            Interface intfH1 = interfaceCfgH1.getInterfaces().stream().findFirst().get();
            Interface intfH2 = interfaceCfgH2.getInterfaces().stream().findFirst().get();

            if (source.vlan().equals(VlanId.NONE) && !destination.vlan().equals(VlanId.NONE)) {
                return intfH1.vlanUntagged().equals(destination.vlan()) ||
                        intfH1.vlanNative().equals(destination.vlan());
            }

            if (!source.vlan().equals(VlanId.NONE) && destination.vlan().equals(VlanId.NONE)) {
                return intfH2.vlanUntagged().equals(source.vlan()) ||
                        intfH2.vlanNative().equals(source.vlan());
            }

            if (!intfH1.vlanNative().equals(intfH2.vlanNative())) {
                return false;
            }

            if (!intfH1.vlanUntagged().equals(intfH2.vlanUntagged())) {
                return false;
            }

            List<InterfaceIpAddress> intersection = new ArrayList<>(intfH1.ipAddressesList());
            intersection.retainAll(intfH2.ipAddressesList());
            if (intersection.size() == 0) {
                return false;
            }
        }
        return true;
    }

    @Override
    public StaticPacketTrace trace(TrafficSelector packet, ConnectPoint in) {
        log.info("Tracing packet {} coming in through {}", packet, in);
        //device must exist in ONOS
        Preconditions.checkNotNull(deviceNib.getDevice(in.deviceId()),
                "Device " + in.deviceId() + " must exist in ONOS");

        StaticPacketTrace trace = new StaticPacketTrace(packet, in);
        boolean isDualHomed = getHosts(trace).stream().anyMatch(host -> host.locations().size() > 1);
        //FIXME this can be done recursively
        //Building output connect Points
        List<ConnectPoint> path = new ArrayList<>();
        trace = traceInDevice(trace, packet, in, isDualHomed, path);
        trace = getTrace(path, in, trace, isDualHomed);
        return trace;
    }

    /**
     * Computes a trace for a give packet that start in the network at the given connect point.
     *
     * @param completePath the path traversed by the packet
     * @param in           the input connect point
     * @param trace        the trace to build
     * @param isDualHomed  true if the trace we are doing starts or ends in a dual homed host
     * @return the build trace for that packet.
     */
    private StaticPacketTrace getTrace(List<ConnectPoint> completePath, ConnectPoint in, StaticPacketTrace trace,
                                       boolean isDualHomed) {

        log.debug("------------------------------------------------------------");

        //if the trace already contains the input connect point there is a loop
        if (pathContainsDevice(completePath, in.deviceId())) {
            trace.addResultMessage("Loop encountered in device " + in.deviceId());
            completePath.add(in);
            trace.addCompletePath(completePath);
            trace.setSuccess(false);
            return trace;
        }

        //let's add the input connect point
        completePath.add(in);

        //If the trace has no outputs for the given input we stop here
        if (trace.getHitChains(in.deviceId()) == null) {
            TroubleshootUtils.computePath(completePath, trace, null);
            trace.addResultMessage("No output out of device " + in.deviceId() + ". Packet is dropped");
            trace.setSuccess(false);
            return trace;
        }

        //If the trace has outputs we analyze them all
        for (PipelineTraceableHitChain outputPath : trace.getHitChains(in.deviceId())) {

            ConnectPoint cp = outputPath.getOutputPort();
            log.debug("Connect point in {}", in);
            log.debug("Output path {}", cp);
            log.debug("{}", outputPath.getEgressPacket());

            if (outputPath.isDropped()) {
                continue;
            }

            //Hosts for the the given output
            Set<Host> hostsList = hostNib.getConnectedHosts(cp);
            //Hosts queried from the original ip or mac
            Set<Host> hosts = getHosts(trace);

            if (in.equals(cp) && trace.getInitialPacket().getCriterion(Criterion.Type.VLAN_VID) != null &&
                    outputPath.getEgressPacket().getCriterion(Criterion.Type.VLAN_VID) != null
                    && ((VlanIdCriterion) trace.getInitialPacket().getCriterion(Criterion.Type.VLAN_VID)).vlanId()
                    .equals(((VlanIdCriterion) outputPath.getEgressPacket().getCriterion(Criterion.Type.VLAN_VID))
                            .vlanId())) {
                if (trace.getHitChains(in.deviceId()).size() == 1 &&
                        TroubleshootUtils.computePath(completePath, trace, outputPath.getOutputPort())) {
                    trace.addResultMessage("Connect point out " + cp + " is same as initial input " + in);
                    trace.setSuccess(false);
                }
            } else if (!Collections.disjoint(hostsList, hosts)) {
                //If the two host collections contain the same item it means we reached the proper output
                log.debug("Stopping here because host is expected destination, reached through {}", completePath);
                if (TroubleshootUtils.computePath(completePath, trace, outputPath.getOutputPort())) {
                    trace.addResultMessage("Reached required destination Host " + cp);
                    trace.setSuccess(true);
                }
                break;

            } else if (cp.port().equals(PortNumber.CONTROLLER)) {
                //Getting the master when the packet gets sent as packet in
                NodeId master = mastershipNib.getMasterFor(cp.deviceId());
                // TODO if we don't need to print master node id, exclude mastership NIB which is used only here
                trace.addResultMessage(PACKET_TO_CONTROLLER + " " + master.id());
                TroubleshootUtils.computePath(completePath, trace, outputPath.getOutputPort());
            } else if (linkNib.getEgressLinks(cp).size() > 0) {
                //TODO this can be optimized if we use a Tree structure for paths.
                //if we already have outputs let's check if the one we are considering starts from one of the devices
                // in any of the ones we have.
                if (trace.getCompletePaths().size() > 0) {
                    ConnectPoint inputForOutput = null;
                    List<ConnectPoint> previousPath = new ArrayList<>();
                    for (List<ConnectPoint> path : trace.getCompletePaths()) {
                        for (ConnectPoint connect : path) {
                            //if the path already contains the input for the output we've found we use it
                            if (connect.equals(in)) {
                                inputForOutput = connect;
                                previousPath = path;
                                break;
                            }
                        }
                    }

                    //we use the pre-existing path up to the point we fork to a new output
                    if (inputForOutput != null && completePath.contains(inputForOutput)) {
                        List<ConnectPoint> temp = new ArrayList<>(previousPath);
                        temp = temp.subList(0, previousPath.indexOf(inputForOutput) + 1);
                        if (completePath.containsAll(temp)) {
                            completePath = temp;
                        }
                    }
                }

                //let's add the ouput for the input
                completePath.add(cp);
                //let's compute the links for the given output
                Set<Link> links = linkNib.getEgressLinks(cp);
                log.debug("Egress Links {}", links);
                //For each link we trace the corresponding device
                for (Link link : links) {
                    ConnectPoint dst = link.dst();
                    //change in-port to the dst link in port
                    Builder updatedPacket = DefaultTrafficSelector.builder();
                    outputPath.getEgressPacket().criteria().forEach(updatedPacket::add);
                    updatedPacket.add(Criteria.matchInPort(dst.port()));
                    log.debug("DST Connect Point {}", dst);
                    //build the elements for that device
                    traceInDevice(trace, updatedPacket.build(), dst, isDualHomed, completePath);
                    //continue the trace along the path
                    getTrace(completePath, dst, trace, isDualHomed);
                }
            } else if (edgePortNib.isEdgePoint(outputPath.getOutputPort()) &&
                    trace.getInitialPacket().getCriterion(Criterion.Type.ETH_DST) != null &&
                    ((EthCriterion) trace.getInitialPacket().getCriterion(Criterion.Type.ETH_DST))
                            .mac().isMulticast()) {
                trace.addResultMessage("Packet is multicast and reached output " + outputPath.getOutputPort() +
                        " which is enabled and is edge port");
                trace.setSuccess(true);
                TroubleshootUtils.computePath(completePath, trace, outputPath.getOutputPort());
                if (!hasOtherOutput(in.deviceId(), trace, outputPath.getOutputPort())) {
                    return trace;
                }
            } else if (deviceNib.getPort(cp) != null && deviceNib.getPort(cp).isEnabled()) {
                EthTypeCriterion ethTypeCriterion = (EthTypeCriterion) trace.getInitialPacket()
                        .getCriterion(Criterion.Type.ETH_TYPE);
                //We treat as correct output only if it's not LLDP or BDDP
                if (!(ethTypeCriterion.ethType().equals(EtherType.LLDP.ethType())
                        && !ethTypeCriterion.ethType().equals(EtherType.BDDP.ethType()))) {
                    if (TroubleshootUtils.computePath(completePath, trace, outputPath.getOutputPort())) {
                        if (hostsList.isEmpty()) {
                            trace.addResultMessage("Packet is " + ((EthTypeCriterion) outputPath.getEgressPacket()
                                    .getCriterion(Criterion.Type.ETH_TYPE)).ethType() + " and reached " +
                                    cp + " with no hosts connected ");
                        } else {
                            IpAddress ipAddress = null;
                            if (trace.getInitialPacket().getCriterion(Criterion.Type.IPV4_DST) != null) {
                                ipAddress = ((IPCriterion) trace.getInitialPacket()
                                        .getCriterion(Criterion.Type.IPV4_DST)).ip().address();
                            } else if (trace.getInitialPacket().getCriterion(Criterion.Type.IPV6_DST) != null) {
                                ipAddress = ((IPCriterion) trace.getInitialPacket()
                                        .getCriterion(Criterion.Type.IPV6_DST)).ip().address();
                            }
                            if (ipAddress != null) {
                                IpAddress finalIpAddress = ipAddress;
                                if (hostsList.stream().anyMatch(host -> host.ipAddresses().contains(finalIpAddress)) ||
                                        hostNib.getHostsByIp(finalIpAddress).isEmpty()) {
                                    trace.addResultMessage("Packet is " +
                                            ((EthTypeCriterion) outputPath.getEgressPacket()
                                                    .getCriterion(Criterion.Type.ETH_TYPE)).ethType() +
                                            " and reached " + cp + " with hosts " + hostsList);
                                } else {
                                    trace.addResultMessage("Wrong output " + cp + " for required destination ip " +
                                            ipAddress);
                                    trace.setSuccess(false);
                                }
                            } else {
                                trace.addResultMessage("Packet is " + ((EthTypeCriterion) outputPath.getEgressPacket()
                                        .getCriterion(Criterion.Type.ETH_TYPE)).ethType() + " and reached " +
                                        cp + " with hosts " + hostsList);
                            }
                        }
                        trace.setSuccess(true);
                    }
                }

            } else {
                TroubleshootUtils.computePath(completePath, trace, cp);
                trace.setSuccess(false);
                if (deviceNib.getPort(cp) == null) {
                    //Port is not existent on device.
                    log.warn("Port {} is not available on device.", cp);
                    trace.addResultMessage("Port " + cp + "is not available on device. Packet is dropped");
                } else {
                    //No links means that the packet gets dropped.
                    log.warn("No links out of {}", cp);
                    trace.addResultMessage("No links depart from " + cp + ". Packet is dropped");
                }
            }
        }
        return trace;
    }

    /**
     * Checks if the device has other outputs than the given connect point.
     *
     * @param inDeviceId the device
     * @param trace      the trace we are building
     * @param cp         an output connect point
     * @return true if the device has other outputs.
     */
    private boolean hasOtherOutput(DeviceId inDeviceId, StaticPacketTrace trace, ConnectPoint cp) {
        return trace.getHitChains(inDeviceId).stream().filter(groupsInDevice ->
                !groupsInDevice.getOutputPort().equals(cp)).count() > 0;
    }

    /**
     * Checks if the path contains the device.
     *
     * @param completePath the path
     * @param deviceId     the device to check
     * @return true if the path contains the device
     */
    //TODO might prove costly, improvement: a class with both CPs and DeviceIds point.
    private boolean pathContainsDevice(List<ConnectPoint> completePath, DeviceId deviceId) {
        for (ConnectPoint cp : completePath) {
            if (cp.deviceId().equals(deviceId)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Gets the hosts for the given initial packet.
     *
     * @param trace the trace we are building
     * @return set of the hosts we are trying to reach
     */
    private Set<Host> getHosts(StaticPacketTrace trace) {
        IPCriterion ipv4Criterion = ((IPCriterion) trace.getInitialPacket()
                .getCriterion(Criterion.Type.IPV4_DST));
        IPCriterion ipv6Criterion = ((IPCriterion) trace.getInitialPacket()
                .getCriterion(Criterion.Type.IPV6_DST));
        Set<Host> hosts = new HashSet<>();
        if (ipv4Criterion != null) {
            hosts.addAll(hostNib.getHostsByIp(ipv4Criterion.ip().address()));
        }
        if (ipv6Criterion != null) {
            hosts.addAll(hostNib.getHostsByIp(ipv6Criterion.ip().address()));
        }
        EthCriterion ethCriterion = ((EthCriterion) trace.getInitialPacket()
                .getCriterion(Criterion.Type.ETH_DST));
        if (ethCriterion != null) {
            hosts.addAll(hostNib.getHostsByMac(ethCriterion.mac()));
        }
        return hosts;
    }

    /**
     * Traces the packet inside a device starting from an input connect point.
     *
     * @param trace        the trace we are building
     * @param packet       the packet we are tracing
     * @param in           the input connect point.
     * @param isDualHomed  true if the trace we are doing starts or ends in a dual homed host
     * @param completePath the path up until this device
     * @return updated trace
     */
    private StaticPacketTrace traceInDevice(StaticPacketTrace trace, TrafficSelector packet, ConnectPoint in,
                                            boolean isDualHomed, List<ConnectPoint> completePath) {
        // Get the behavior - do not proceed if there is no PipelineMatchable for the given device
        PipelineTraceable pipelineMatchable = getPipelineMatchable(in.deviceId());
        if (pipelineMatchable == null) {
            trace.addResultMessage("No PipelineMatchable behavior for " + in.deviceId() + ". Aborting");
            TroubleshootUtils.computePath(completePath, trace, null);
            trace.setSuccess(false);
            return trace;
        }

        // Verify the presence of multiple routes - if the device has been visited in the past
        boolean multipleRoutes = false;
        if (trace.getHitChains(in.deviceId()) != null) {
            multipleRoutes = multipleRoutes(trace);
        }
        if (trace.getHitChains(in.deviceId()) != null && !isDualHomed && !multipleRoutes) {
            log.debug("Trace already contains device and given outputs");
            return trace;
        }

        log.debug("Packet {} coming in from {}", packet, in);

        //if device is not available exit here.
        if (!deviceNib.isAvailable(in.deviceId())) {
            trace.addResultMessage("Device is offline " + in.deviceId());
            TroubleshootUtils.computePath(completePath, trace, null);
            return trace;
        }

        // Handle when the input is the controller.
        // NOTE, we are using the input port as a convenience to carry the CONTROLLER port number even if
        // a packet in from the controller will not actually traverse the pipeline and have no such notion
        // as the input port.
        if (in.port().equals(PortNumber.CONTROLLER)) {
            StaticPacketTrace outputTrace = inputFromController(trace, in);
            if (outputTrace != null) {
                return trace;
            }
        }

        // Get the device state in the form of DataPlaneEntity objects - do not proceed if there is no state
        List<DataPlaneEntity> dataPlaneEntities = getDataPlaneEntities(in.deviceId());
        if (dataPlaneEntities.isEmpty()) {
            trace.addResultMessage("No device state for " + in.deviceId() + ". Aborting");
            TroubleshootUtils.computePath(completePath, trace, null);
            trace.setSuccess(false);
            return trace;
        }

        // Applies pipeline processing
        PipelineTraceableInput input = new PipelineTraceableInput(packet, in, dataPlaneEntities);
        PipelineTraceableOutput output = pipelineMatchable.apply(input);

        // Update the trace
        List<PipelineTraceableHitChain> hitChains = output.getHitChains();
        hitChains.forEach(hitChain -> trace.addHitChain(in.deviceId(), hitChain));
        trace.addResultMessage(output.getLog());

        // If there was an error set the success to false
        if (output.getResult() != PipelineTraceableResult.SUCCESS) {
            TroubleshootUtils.computePath(completePath, trace, null);
            trace.setSuccess(false);
        }

        log.info("Logs -> {}", output.getLog());
        hitChains.forEach(hitChain -> log.info("HitChain -> {}", hitChain));

        // We are done!
        return trace;
    }

    // Compute whether or not there are multiple routes.
    private boolean multipleRoutes(StaticPacketTrace trace) {
        boolean multipleRoutes = false;
        IPCriterion ipCriterion = ((IPCriterion) trace.getInitialPacket().getCriterion(Criterion.Type.IPV4_DST));
        IpAddress ip = null;
        if (ipCriterion != null) {
            ip = ipCriterion.ip().address();
        } else if (trace.getInitialPacket().getCriterion(Criterion.Type.IPV6_DST) != null) {
            ip = ((IPCriterion) trace.getInitialPacket().getCriterion(Criterion.Type.IPV6_DST)).ip().address();
        }
        if (ip != null) {
            Optional<ResolvedRoute> optionalRoute = routeNib.longestPrefixLookup(ip);
            if (optionalRoute.isPresent()) {
                ResolvedRoute route = optionalRoute.get();
                multipleRoutes = routeNib.getAllResolvedRoutes(route.prefix()).size() > 1;
            }
        }
        return multipleRoutes;
    }

    /**
     * Handles the specific case where the Input is the controller.
     * Note that the in port is used as a convenience to store the port of the controller even if the packet in
     * from a controller should not have a physical input port. The in port from the Controller is used to make sure
     * the flood to all active physical ports of the device.
     *
     * @param trace the trace
     * @param in    the controller port
     * @return the augmented trace.
     */
    private StaticPacketTrace inputFromController(StaticPacketTrace trace, ConnectPoint in) {
        EthTypeCriterion ethTypeCriterion = (EthTypeCriterion) trace.getInitialPacket()
                .getCriterion(Criterion.Type.ETH_TYPE);
        //If the packet is LLDP or BDDP we flood it on all active ports of the switch.
        if (ethTypeCriterion != null && (ethTypeCriterion.ethType().equals(EtherType.LLDP.ethType())
                || ethTypeCriterion.ethType().equals(EtherType.BDDP.ethType()))) {
            //get the active ports
            List<Port> enabledPorts = deviceNib.getPorts(in.deviceId()).stream()
                    .filter(Port::isEnabled)
                    .collect(Collectors.toList());
            //build an output from each one
            enabledPorts.forEach(port -> {
                PipelineTraceableHitChain hitChain = new PipelineTraceableHitChain(
                        new ConnectPoint(port.element().id(), port.number()), ImmutableList.of(),
                        trace.getInitialPacket());
                trace.addHitChain(in.deviceId(), hitChain);
            });
            return trace;
        }
        return null;
    }

    ////////////////////////////////
    // Cemetery - Deprecated code //
    ////////////////////////////////
    @Override
    public List<StaticPacketTrace> pingAll(EtherType type) {
        ImmutableList.Builder<StaticPacketTrace> tracesBuilder = ImmutableList.builder();
        hostNib.getHosts().forEach(host -> {
            List<IpAddress> ipAddresses = getIpAddresses(host, type, false);
            if (ipAddresses.size() > 0) {
                //check if the host has only local IPs of that ETH type
                boolean onlyLocalSrc = ipAddresses.size() == 1 && ipAddresses.get(0).isLinkLocal();
                hostNib.getHosts().forEach(hostToPing -> {
                    List<IpAddress> ipAddressesToPing = getIpAddresses(hostToPing, type, false);
                    //check if the other host has only local IPs of that ETH type
                    boolean onlyLocalDst = ipAddressesToPing.size() == 1 && ipAddressesToPing.get(0).isLinkLocal();
                    boolean sameLocation = Sets.intersection(host.locations(), hostToPing.locations()).size() > 0;
                    //Trace is done only if they are both local and under the same location
                    // or not local and if they are not the same host.
                    if (((sameLocation && onlyLocalDst && onlyLocalSrc) ||
                            (!onlyLocalSrc && !onlyLocalDst && ipAddressesToPing.size() > 0))
                            && !host.equals(hostToPing)) {
                        tracesBuilder.addAll(trace(host.id(), hostToPing.id(), type));
                    }
                });
            }
        });
        return tracesBuilder.build();
    }

    @Override
    public List<Set<StaticPacketTrace>> getMulitcastTrace(VlanId vlanId) {
        Generator<Set<StaticPacketTrace>> gen = new McastGenerator(mcastRouteNib, this, vlanId);
        List<Set<StaticPacketTrace>> multicastTraceList =
                StreamSupport.stream(gen.spliterator(), false).collect(Collectors.toList());
        return multicastTraceList;
    }

}
