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
package org.onosproject.t3.impl;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Test;
import org.onlab.packet.ChassisId;
import org.onlab.packet.EthType;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.cluster.NodeId;
import org.onosproject.driver.pipeline.ofdpa.Ofdpa2Pipeline;
import org.onosproject.driver.traceable.OfdpaPipelineTraceable;
import org.onosproject.net.AbstractProjectableModel;
import org.onosproject.net.AnnotationKeys;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.DefaultAnnotations;
import org.onosproject.net.DefaultDevice;
import org.onosproject.net.DefaultLink;
import org.onosproject.net.DefaultPort;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.Link;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.SparseAnnotations;
import org.onosproject.net.behaviour.PipelineTraceable;
import org.onosproject.net.driver.Behaviour;
import org.onosproject.net.driver.Driver;
import org.onosproject.net.driver.DriverAdapter;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.driver.DriverService;
import org.onosproject.net.driver.DriverServiceAdapter;
import org.onosproject.net.driver.HandlerBehaviour;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthTypeCriterion;
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.group.Group;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.routeservice.ResolvedRoute;
import org.onosproject.t3.api.DeviceNib;
import org.onosproject.t3.api.DriverNib;
import org.onosproject.t3.api.EdgePortNib;
import org.onosproject.t3.api.FlowNib;
import org.onosproject.t3.api.GroupNib;
import org.onosproject.t3.api.HostNib;
import org.onosproject.t3.api.LinkNib;
import org.onosproject.t3.api.MastershipNib;
import org.onosproject.t3.api.RouteNib;
import org.onosproject.t3.api.StaticPacketTrace;
import org.slf4j.Logger;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.onosproject.net.Device.Type.SWITCH;
import static org.onosproject.t3.impl.T3TestObjects.*;
import static org.onosproject.t3.impl.TroubleshootManager.PACKET_TO_CONTROLLER;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Test Class for Troubleshoot Manager.
 */
public class TroubleshootManagerTest {

    private static final Logger log = getLogger(TroubleshootManager.class);
    private TroubleshootManager mngr;
    private Driver baseDriver = new TestDriver();

    @Before
    public void setUp() throws Exception {
        // Setup step for the device
        DriverService testDeviceService = new TestDriverService();
        AbstractProjectableModel.setDriverService(null, testDeviceService);

        mngr = new TroubleshootManager();

        mngr.flowNib = new TestFlowRuleService();
        mngr.groupNib = new TestGroupService();
        mngr.hostNib = new TestHostService();
        mngr.linkNib = new TestLinkService();
        mngr.deviceNib = new TestDeviceService();
        mngr.driverNib = new TestDriverNib();
        mngr.mastershipNib = new TestMastershipService();
        mngr.edgePortNib = new TestEdgePortService();
        mngr.routeNib = new TestRouteService();

        assertNotNull("Manager should not be null", mngr);

        assertNotNull("Flow rule Service should not be null", mngr.flowNib);
        assertNotNull("Group Service should not be null", mngr.groupNib);
        assertNotNull("Host Service should not be null", mngr.hostNib);
        assertNotNull("Link Service should not be null", mngr.linkNib);
        assertNotNull("Device Service should not be null", mngr.deviceNib);
        assertNotNull("Driver Service should not be null", mngr.driverNib);
        assertNotNull("Mastership Service should not be null", mngr.driverNib);
        assertNotNull("EdgePort Service should not be null", mngr.driverNib);
        assertNotNull("Route Service should not be null", mngr.routeNib);
    }

    /**
     * Tests failure on non existent device.
     */
    @Test(expected = NullPointerException.class)
    public void nonExistentDevice() {
        StaticPacketTrace traceFail = mngr.trace(PACKET_OK, ConnectPoint.deviceConnectPoint("nonexistent" + "/1"));
        log.info("trace {}", traceFail.resultMessage());
    }

    /**
     * Tests failure on offline device.
     */
    @Test
    public void offlineDevice() {
        StaticPacketTrace traceFail = mngr.trace(PACKET_OK, ConnectPoint.deviceConnectPoint(OFFLINE_DEVICE + "/1"));
        assertNotNull("Trace should not be null", traceFail);
        assertTrue("Device should be offline",
                traceFail.resultMessage().contains("Device is offline"));
        assertNull("Trace should have 0 output", traceFail.getHitChains(SINGLE_FLOW_DEVICE));
        log.info("trace {}", traceFail.resultMessage());
    }

    /**
     * Tests failure on same output.
     */
    @Test
    public void sameOutput() {
        StaticPacketTrace traceFail = mngr.trace(PACKET_OK, SAME_OUTPUT_FLOW_CP);
        assertNotNull("Trace should not be null", traceFail);
        assertTrue("Trace should be unsuccessful",
                traceFail.resultMessage().contains("is same as initial input"));
        log.info("trace {}", traceFail.resultMessage());
    }

    /**
     * Tests ARP to controller.
     */
    @Test
    public void arpToController() {
        StaticPacketTrace traceSuccess = mngr.trace(PACKET_ARP, ARP_FLOW_CP);
        assertNotNull("Trace should not be null", traceSuccess);
        assertTrue("Trace should be successful",
                traceSuccess.resultMessage().contains(PACKET_TO_CONTROLLER));
        assertTrue("Master should be Master1",
                traceSuccess.resultMessage().contains(MASTER_1));
        ConnectPoint connectPoint = traceSuccess.getHitChains(ARP_FLOW_DEVICE).get(0).getOutputPort();
        assertEquals("Packet Should go to CONTROLLER", PortNumber.CONTROLLER, connectPoint.port());
        VlanIdCriterion vlanIdCriterion = (VlanIdCriterion) traceSuccess.getHitChains(ARP_FLOW_DEVICE).get(0)
                .getEgressPacket().getCriterion(Criterion.Type.VLAN_VID);
        assertEquals("VlanId should be None", VlanId.NONE, vlanIdCriterion.vlanId());
        log.info("trace {}", traceSuccess.resultMessage());
    }

    /**
     * Tests ARP to controller and Vlan id removal.
     */
    @Test
    public void arpToControllerVlan() {
        StaticPacketTrace traceSuccess = mngr.trace(PACKET_ARP, ARP_FLOW_VLAN_CP);
        assertNotNull("Trace should not be null", traceSuccess);
        assertTrue("Trace should be successful",
                traceSuccess.resultMessage().contains(PACKET_TO_CONTROLLER));
        assertTrue("Master should be Master1",
                traceSuccess.resultMessage().contains(MASTER_1));
        ConnectPoint connectPoint = traceSuccess.getHitChains(ARP_FLOW_VLAN_DEVICE).get(0).getOutputPort();
        assertEquals("Packet Should go to CONTROLLER", PortNumber.CONTROLLER, connectPoint.port());
        VlanIdCriterion vlanIdCriterion = (VlanIdCriterion) traceSuccess.getHitChains(ARP_FLOW_VLAN_DEVICE).get(0)
                .getEgressPacket().getCriterion(Criterion.Type.VLAN_VID);
        assertEquals("VlanId should be None", VlanId.NONE, vlanIdCriterion.vlanId());
        log.info("trace {}", traceSuccess.resultMessage());
    }

    /**
     * Tests failure on device with no flows.
     */
    @Test
    public void noFlows() {
        StaticPacketTrace traceFail = mngr.trace(PACKET_OK, ConnectPoint.deviceConnectPoint("test/1"));
        assertNotNull("Trace should not be null", traceFail);
        assertNull("Trace should have 0 output", traceFail.getHitChains(SINGLE_FLOW_DEVICE));
        log.info("trace {}", traceFail.resultMessage());
    }

    /**
     * Test group with no buckets.
     */
    @Test
    public void noBucketsTest() {
        StaticPacketTrace traceFail = mngr.trace(PACKET_OK, NO_BUCKET_CP);
        assertNotNull("Trace should not be null", traceFail);
        assertTrue("Trace should be unsuccessful",
                traceFail.resultMessage().contains("no buckets"));
        log.info("trace {}", traceFail.resultMessage());
    }

    /**
     * Test a single flow rule that has output port in it.
     */
    @Test
    public void testSingleFlowRule() {
        // Happy ending
        testSuccess(PACKET_OK, SINGLE_FLOW_IN_CP, SINGLE_FLOW_DEVICE, SINGLE_FLOW_OUT_CP, 1, 1);
        // Failure scenario
        testFailure(PACKET_FAIL, SINGLE_FLOW_IN_CP, SINGLE_FLOW_DEVICE, 1);
    }

    /**
     * Tests two flow rule the last one of which has output port in it.
     */
    @Test
    public void testDualFlowRule() {
        // Test Success
        StaticPacketTrace traceSuccess = testSuccess(PACKET_OK, DUAL_FLOW_IN_CP, DUAL_FLOW_DEVICE,
                DUAL_FLOW_OUT_CP, 1, 1);
        // Verifying Vlan
        Criterion criterion = traceSuccess.getHitChains(DUAL_FLOW_DEVICE).get(0).
                getEgressPacket().getCriterion(Criterion.Type.VLAN_VID);
        assertNotNull("Packet Should have Vlan", criterion);
        VlanIdCriterion vlanIdCriterion = (VlanIdCriterion) criterion;
        assertEquals("Vlan should be 100", VlanId.vlanId((short) 100), vlanIdCriterion.vlanId());

        // Test Failure
        testFailure(PACKET_FAIL, DUAL_FLOW_IN_CP, DUAL_FLOW_DEVICE, 1);
    }

    /**
     * Test a single flow rule that points to a group with output port in it.
     */
    @Test
    public void flowAndGroup() {
        // Test Success
        StaticPacketTrace traceSuccess = testSuccess(PACKET_OK, GROUP_FLOW_IN_CP, GROUP_FLOW_DEVICE,
                GROUP_FLOW_OUT_CP, 1, 1);
        // Verify the output of the test
        assertTrue("Wrong Output Group", traceSuccess.getHitChains(GROUP_FLOW_DEVICE)
                .get(0).getHitChain().contains(new DataPlaneEntity(GROUP)));
        assertEquals("Packet should not have MPLS Label", EthType.EtherType.IPV4.ethType(),
                ((EthTypeCriterion) traceSuccess.getHitChains(GROUP_FLOW_DEVICE)
                        .get(0).getEgressPacket().getCriterion(Criterion.Type.ETH_TYPE)).ethType());
        assertNull("Packet should not have MPLS Label", traceSuccess.getHitChains(GROUP_FLOW_DEVICE)
                .get(0).getEgressPacket().getCriterion(Criterion.Type.MPLS_LABEL));
        assertNull("Packet should not have MPLS BoS", traceSuccess.getHitChains(GROUP_FLOW_DEVICE)
                .get(0).getEgressPacket().getCriterion(Criterion.Type.MPLS_BOS));
    }

    /**
     * Test path through a 3 device topology.
     */
    @Test
    public void singlePathTopology() {
        // Test success
        StaticPacketTrace traceSuccess = testSuccess(PACKET_OK_TOPO, TOPO_FLOW_1_IN_CP,
                TOPO_FLOW_3_DEVICE, TOPO_FLOW_3_OUT_CP, 1, 1);
        // Verify that the complete path contains all the traversed connect points
        List<ConnectPoint> path = Lists.newArrayList(TOPO_FLOW_1_IN_CP, TOPO_FLOW_1_OUT_CP,
                TOPO_FLOW_2_IN_CP, TOPO_FLOW_2_OUT_CP, TOPO_FLOW_3_IN_CP, TOPO_FLOW_3_OUT_CP);
        assertEquals(path, traceSuccess.getCompletePaths().get(0));
    }

    /**
     * Test path through a 4 device topology with first device that has groups with multiple output buckets.
     */
    @Test
    public void testGroupTopo() {
        // Test success
        StaticPacketTrace traceSuccess = testSuccess(PACKET_OK_TOPO, TOPO_FLOW_IN_CP,
                TOPO_FLOW_3_DEVICE, TOPO_FLOW_3_OUT_CP, 2, 1);
        // Verify the multiple output actions
        assertTrue("Incorrect groups",
                traceSuccess.getHitChains(TOPO_GROUP_FLOW_DEVICE).get(0).getHitChain()
                        .contains(new DataPlaneEntity(TOPO_GROUP)));
        assertTrue("Incorrect bucket",
                traceSuccess.getHitChains(TOPO_GROUP_FLOW_DEVICE).get(1).getHitChain()
                        .contains(new DataPlaneEntity(TOPO_GROUP)));
    }

    /**
     * Test dual links between 3 topology elements.
     */
    @Test
    public void dualLinks() {
        // Success
        StaticPacketTrace traceSuccess = testSuccess(PACKET_OK, DUAL_LINK_1_CP_1_IN,
                DUAL_LINK_3, DUAL_LINK_3_CP_3_OUT, 4, 1);
        // Verify that the complete path contains all the traversed connect points
        List<ConnectPoint> path = Lists.newArrayList(DUAL_LINK_1_CP_1_IN, DUAL_LINK_1_CP_2_OUT,
                DUAL_LINK_2_CP_1_IN, DUAL_LINK_2_CP_2_OUT, DUAL_LINK_3_CP_1_IN, DUAL_LINK_3_CP_3_OUT);
        assertTrue(traceSuccess.getCompletePaths().contains(path));
        path = Lists.newArrayList(DUAL_LINK_1_CP_1_IN, DUAL_LINK_1_CP_2_OUT,
                DUAL_LINK_2_CP_1_IN, DUAL_LINK_2_CP_3_OUT, DUAL_LINK_3_CP_2_IN, DUAL_LINK_3_CP_3_OUT);
        assertTrue(traceSuccess.getCompletePaths().contains(path));
        path = Lists.newArrayList(DUAL_LINK_1_CP_1_IN, DUAL_LINK_1_CP_3_OUT,
                DUAL_LINK_2_CP_4_IN, DUAL_LINK_2_CP_2_OUT, DUAL_LINK_3_CP_1_IN, DUAL_LINK_3_CP_3_OUT);
        assertTrue(traceSuccess.getCompletePaths().contains(path));
        path = Lists.newArrayList(DUAL_LINK_1_CP_1_IN, DUAL_LINK_1_CP_3_OUT,
                DUAL_LINK_2_CP_4_IN, DUAL_LINK_2_CP_3_OUT, DUAL_LINK_3_CP_2_IN, DUAL_LINK_3_CP_3_OUT);
        assertTrue(traceSuccess.getCompletePaths().contains(path));
    }

    /**
     * Test LLDP output to controller.
     */
    @Test
    public void lldpToController() {
        StaticPacketTrace traceSuccess = mngr.trace(PACKET_LLDP, LLDP_FLOW_CP);
        assertNotNull("Trace should not be null", traceSuccess);
        assertTrue("Trace should be successful",
                traceSuccess.resultMessage().contains("Packet goes to the controller"));
        assertTrue("Master should be Master1",
                traceSuccess.resultMessage().contains(MASTER_1));
        ConnectPoint connectPoint = traceSuccess.getHitChains(LLDP_FLOW_DEVICE).get(0).getOutputPort();
        assertEquals("Packet Should go to CONTROLLER", PortNumber.CONTROLLER, connectPoint.port());
        log.info("trace {}", traceSuccess.resultMessage());
    }

    /**
     * Test multicast in single device.
     */
    @Test
    public void multicastTest() {
        // Test success
        StaticPacketTrace traceSuccess = mngr.trace(PACKET_OK_MULTICAST, MULTICAST_IN_CP);
        log.info("trace {}", traceSuccess);
        log.info("trace {}", traceSuccess.resultMessage());

        // Verify some conditions on the test
        assertNotNull("trace should not be null", traceSuccess);
        assertEquals("Trace should have " + 2 + " hitchains", 2,
                traceSuccess.getHitChains(MULTICAST_GROUP_FLOW_DEVICE).size());
        assertEquals("Trace should only have " + 2 + "paths", 2,
                traceSuccess.getCompletePaths().size());
        assertTrue("Trace should be successful",
                traceSuccess.resultMessage().contains("reached output"));
        assertEquals("Incorrect Output CP", MULTICAST_OUT_CP_2,
                traceSuccess.getHitChains(MULTICAST_GROUP_FLOW_DEVICE).get(0).getOutputPort());
        assertEquals("Incorrect Output CP", MULTICAST_OUT_CP,
                traceSuccess.getHitChains(MULTICAST_GROUP_FLOW_DEVICE).get(1).getOutputPort());
    }

    /**
     * Tests dual homing of a host.
     */
    @Test
    public void dualhomedTest() {
        // Test success
        StaticPacketTrace traceSuccess = mngr.trace(PACKET_DUAL_HOME, DUAL_HOME_CP_1_1);
        log.info("trace {}", traceSuccess);
        log.info("trace {}", traceSuccess.resultMessage());

        // Verify paths
        assertNotNull("trace should not be null", traceSuccess);
        assertEquals("Should have 2 output paths", 2, traceSuccess.getCompletePaths().size());
        assertTrue("Should contain proper path", traceSuccess.getCompletePaths()
                .contains(ImmutableList.of(DUAL_HOME_CP_1_1, DUAL_HOME_CP_1_2, DUAL_HOME_CP_2_1, DUAL_HOME_CP_2_2)));
        assertTrue("Should contain proper path", traceSuccess.getCompletePaths()
                .contains(ImmutableList.of(DUAL_HOME_CP_1_1, DUAL_HOME_CP_1_3, DUAL_HOME_CP_3_1, DUAL_HOME_CP_3_2)));

    }

    private StaticPacketTrace testSuccess(TrafficSelector packet, ConnectPoint in, DeviceId deviceId,
                                          ConnectPoint out, int paths, int hitchains) {
        StaticPacketTrace traceSuccess = mngr.trace(packet, in);
        log.info("trace {}", traceSuccess);
        log.info("trace {}", traceSuccess.resultMessage());

        assertNotNull("trace should not be null", traceSuccess);
        assertEquals("Trace should have " + hitchains + " hitchains", hitchains,
                traceSuccess.getHitChains(deviceId).size());
        assertEquals("Trace should only have " + paths + "output", paths, traceSuccess.getCompletePaths().size());
        assertTrue("Trace should be successful",
                traceSuccess.resultMessage().contains("Reached required destination Host"));
        assertEquals("Incorrect Output CP", out,
                traceSuccess.getHitChains(deviceId).get(0).getOutputPort());

        return traceSuccess;
    }

    private void testFailure(TrafficSelector packet, ConnectPoint in, DeviceId deviceId,
                             int hitchains) {
        StaticPacketTrace traceFail = mngr.trace(packet, in);
        log.info("trace {}", traceFail.resultMessage());

        assertNotNull("Trace should not be null", traceFail);
        assertEquals("Trace should have " + hitchains + " hitchains", hitchains,
                traceFail.getHitChains(deviceId).size());
    }

    private static class TestFlowRuleService extends FlowNib {

        @Override
        public Iterable<FlowEntry> getFlowEntriesByState(DeviceId deviceId, FlowEntry.FlowEntryState state) {
            if (deviceId.equals(SINGLE_FLOW_DEVICE)) {
                return ImmutableList.of(SINGLE_FLOW_ENTRY);
            } else if (deviceId.equals(DUAL_FLOW_DEVICE)) {
                return ImmutableList.of(FIRST_FLOW_ENTRY, SECOND_FLOW_ENTRY);
            } else if (deviceId.equals(GROUP_FLOW_DEVICE)) {
                return ImmutableList.of(GROUP_FLOW_ENTRY);
            } else if (deviceId.equals(TOPO_FLOW_DEVICE) ||
                    deviceId.equals(TOPO_FLOW_2_DEVICE) ||
                    deviceId.equals(TOPO_FLOW_3_DEVICE) ||
                    deviceId.equals(TOPO_FLOW_4_DEVICE)) {
                return ImmutableList.of(TOPO_SINGLE_FLOW_ENTRY, TOPO_SECOND_INPUT_FLOW_ENTRY);
            } else if (deviceId.equals(TOPO_GROUP_FLOW_DEVICE)) {
                return ImmutableList.of(TOPO_GROUP_FLOW_ENTRY);
            } else if (deviceId.equals(SAME_OUTPUT_FLOW_DEVICE)) {
                return ImmutableList.of(SAME_OUTPUT_FLOW_ENTRY);
            } else if (deviceId.equals(ARP_FLOW_DEVICE)) {
                    return ImmutableList.of(ARP_FLOW_ENTRY);
            } else if (deviceId.equals(ARP_FLOW_VLAN_DEVICE)) {
                return ImmutableList.of(ARP_FLOW_VLAN_ENTRY, ARP_FLOW_ENTRY);
            } else if (deviceId.equals(DUAL_LINK_1)) {
                return ImmutableList.of(DUAL_LINK_1_GROUP_FLOW_ENTRY);
            } else if (deviceId.equals(DUAL_LINK_2)) {
                return ImmutableList.of(DUAL_LINK_1_GROUP_FLOW_ENTRY, DUAL_LINK_2_GROUP_FLOW_ENTRY);
            } else if (deviceId.equals(DUAL_LINK_3)) {
                return ImmutableList.of(DUAL_LINK_3_FLOW_ENTRY, DUAL_LINK_3_FLOW_ENTRY_2);
            } else if (deviceId.equals(LLDP_FLOW_DEVICE)) {
                return ImmutableList.of(LLDP_FLOW_ENTRY);
            } else if (deviceId.equals(MULTICAST_GROUP_FLOW_DEVICE)) {
                return ImmutableList.of(MULTICAST_GROUP_FLOW_ENTRY);
            } else if (deviceId.equals(NO_BUCKET_DEVICE)) {
                return ImmutableList.of(NO_BUCKET_ENTRY);
            } else if (deviceId.equals(DUAL_HOME_DEVICE_1)) {
                return ImmutableList.of(DUAL_HOME_FLOW_ENTRY);
            } else if (deviceId.equals(DUAL_HOME_DEVICE_2) || deviceId.equals(DUAL_HOME_DEVICE_3)) {
                return ImmutableList.of(DUAL_HOME_OUT_FLOW_ENTRY);
            }
            return ImmutableList.of();
        }
    }

    private static class TestGroupService extends GroupNib {

        @Override
        public Iterable<Group> getGroupsByState(DeviceId deviceId, Group.GroupState groupState) {
            if (deviceId.equals(GROUP_FLOW_DEVICE)) {
                return ImmutableList.of(GROUP);
            } else if (deviceId.equals(TOPO_GROUP_FLOW_DEVICE)) {
                return ImmutableList.of(TOPO_GROUP);
            } else if (deviceId.equals(DUAL_LINK_1) || deviceId.equals(DUAL_LINK_2)) {
                return ImmutableList.of(DUAL_LINK_GROUP);
            } else if (deviceId.equals(MULTICAST_GROUP_FLOW_DEVICE)) {
                return ImmutableList.of(MULTICAST_GROUP);
            } else if (deviceId.equals(NO_BUCKET_DEVICE)) {
                return ImmutableList.of(NO_BUCKET_GROUP);
            } else if (deviceId.equals(DUAL_HOME_DEVICE_1)) {
                return ImmutableList.of(DUAL_HOME_GROUP);
            }
            return ImmutableList.of();
        }
    }

    private static class TestHostService extends HostNib {
        @Override
        public Set<Host> getConnectedHosts(ConnectPoint connectPoint) {
            if (connectPoint.equals(TOPO_FLOW_3_OUT_CP)) {
                return ImmutableSet.of(H2);
            } else if (connectPoint.equals(DUAL_LINK_1_CP_2_OUT) || connectPoint.equals(DUAL_LINK_1_CP_3_OUT) ||
                    connectPoint.equals(DUAL_LINK_2_CP_2_OUT) || connectPoint.equals(DUAL_LINK_2_CP_3_OUT)) {
                return ImmutableSet.of();
            }
            if (connectPoint.equals(SINGLE_FLOW_OUT_CP) ||
                    connectPoint.equals(DUAL_FLOW_OUT_CP) ||
                    connectPoint.equals(GROUP_FLOW_OUT_CP) ||
                    connectPoint.equals(DUAL_LINK_3_CP_3_OUT)) {
                return ImmutableSet.of(H1);
            }
            if (connectPoint.equals(DUAL_HOME_CP_2_2) || connectPoint.equals(DUAL_HOME_CP_3_2)) {
                return ImmutableSet.of(DUAL_HOME_H);
            }
            return ImmutableSet.of();
        }

        @Override
        public Set<Host> getHostsByMac(MacAddress mac) {
            if (mac.equals(H1.mac())) {
                return ImmutableSet.of(H1);
            } else if (mac.equals(H2.mac())) {
                return ImmutableSet.of(H2);
            } else if (mac.equals(DUAL_HOME_H.mac())) {
                return ImmutableSet.of(DUAL_HOME_H);
            }
            return ImmutableSet.of();
        }

        @Override
        public Set<Host> getHostsByIp(IpAddress ip) {
            if ((H1.ipAddresses().contains(ip))) {
                return ImmutableSet.of(H1);
            } else if ((H2.ipAddresses().contains(ip))) {
                return ImmutableSet.of(H2);
            } else if ((DUAL_HOME_H.ipAddresses().contains(ip))) {
                return ImmutableSet.of(DUAL_HOME_H);
            }
            return ImmutableSet.of();
        }
    }

    private static class TestLinkService extends LinkNib {
        @Override
        public Set<Link> getEgressLinks(ConnectPoint connectPoint) {
            if (connectPoint.equals(TOPO_FLOW_1_OUT_CP)
                    || connectPoint.equals(TOPO_FLOW_OUT_CP_1)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(connectPoint)
                        .dst(TOPO_FLOW_2_IN_CP)
                        .build());
            } else if (connectPoint.equals(TOPO_FLOW_2_OUT_CP)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(TOPO_FLOW_2_OUT_CP)
                        .dst(TOPO_FLOW_3_IN_CP)
                        .build());
            } else if (connectPoint.equals(TOPO_FLOW_OUT_CP_2)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(TOPO_FLOW_OUT_CP_2)
                        .dst(TOPO_FLOW_4_IN_CP)
                        .build());
            } else if (connectPoint.equals(TOPO_FLOW_4_OUT_CP)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(TOPO_FLOW_4_OUT_CP)
                        .dst(TOPO_FLOW_3_IN_2_CP)
                        .build());
            } else if (connectPoint.equals(DUAL_LINK_1_CP_2_OUT)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(DUAL_LINK_1_CP_2_OUT)
                        .dst(DUAL_LINK_2_CP_1_IN)
                        .build());
            } else if (connectPoint.equals(DUAL_LINK_1_CP_3_OUT)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(DUAL_LINK_1_CP_3_OUT)
                        .dst(DUAL_LINK_2_CP_4_IN)
                        .build());
            } else if (connectPoint.equals(DUAL_LINK_2_CP_2_OUT)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(DUAL_LINK_2_CP_2_OUT)
                        .dst(DUAL_LINK_3_CP_1_IN)
                        .build());
            } else if (connectPoint.equals(DUAL_LINK_2_CP_3_OUT)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(DUAL_LINK_2_CP_3_OUT)
                        .dst(DUAL_LINK_3_CP_2_IN)
                        .build());
            } else if (connectPoint.equals(DUAL_HOME_CP_1_2)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(DUAL_HOME_CP_1_2)
                        .dst(DUAL_HOME_CP_2_1)
                        .build());
            } else if (connectPoint.equals(DUAL_HOME_CP_1_3)) {
                return ImmutableSet.of(DefaultLink.builder()
                        .providerId(ProviderId.NONE)
                        .type(Link.Type.DIRECT)
                        .src(DUAL_HOME_CP_1_3)
                        .dst(DUAL_HOME_CP_3_1)
                        .build());
            }
            return ImmutableSet.of();
        }
    }

    private static class TestDeviceService extends DeviceNib {
        @Override
        public Device getDevice(DeviceId deviceId) {
            if (deviceId.equals(DeviceId.deviceId("nonexistent"))) {
                return null;
            }
            SparseAnnotations annotations = DefaultAnnotations.builder()
                    .set("foo", "bar")
                    .set(AnnotationKeys.DRIVER, OFDPA_DRIVER)
                    .build();
            return new DefaultDevice(ProviderId.NONE, deviceId, SWITCH,
                    MANUFACTURER, HW_VERSION, SW_VERSION, SERIAL_NUMBER, new ChassisId(),
                    annotations);
        }

        @Override
        public Port getPort(ConnectPoint cp) {
            return new DefaultPort(null, cp.port(), true, DefaultAnnotations.builder().build());
        }

        @Override
        public boolean isAvailable(DeviceId deviceId) {
            return !deviceId.equals(OFFLINE_DEVICE);
        }
    }

    private static class TestDriverNib extends DriverNib {
        @Override
        public String getDriverName(DeviceId deviceId) {
            return "NotHWDriver";
        }
    }

    private static class TestMastershipService extends MastershipNib {
        @Override
        public NodeId getMasterFor(DeviceId deviceId) {
            return NodeId.nodeId(MASTER_1);
        }
    }

    private static class TestEdgePortService extends EdgePortNib {
        @Override
        public boolean isEdgePoint(ConnectPoint point) {
            return point.equals(MULTICAST_OUT_CP) ||
                    point.equals(MULTICAST_OUT_CP_2);
        }
    }

    private static class TestRouteService extends RouteNib {
        @Override
        public Optional<ResolvedRoute> longestPrefixLookup(IpAddress ip) {
            return Optional.empty();
        }
    }

    private class TestDriverService extends DriverServiceAdapter {
        @Override
        public Driver getDriver(DeviceId deviceId) {
            return baseDriver;
        }
    }

    private static class TestDriver extends DriverAdapter {

        @Override
        public String manufacturer() {
            return MANUFACTURER;
        }

        @Override
        public String hwVersion() {
            return HW_VERSION;
        }

        @Override
        public String swVersion() {
            return SW_VERSION;
        }

        @Override
        public String name() {
            return OFDPA_DRIVER;
        }

        @Override
        @SuppressWarnings("unchecked")
        public <T extends Behaviour> T createBehaviour(DriverHandler handler, Class<T> behaviourClass) {
            if (behaviourClass == PipelineTraceable.class) {
                T behaviour = (T) new OfdpaPipelineTraceable();
                behaviour.setData(handler.data());
                ((HandlerBehaviour) behaviour).setHandler(handler);
                return behaviour;
            } else {
                T behaviour = (T) new Ofdpa2Pipeline();
                behaviour.setData(handler.data());
                ((HandlerBehaviour) behaviour).setHandler(handler);
                return behaviour;
            }
        }

    }

}