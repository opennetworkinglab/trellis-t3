/*
 * Copyright 2015-present Open Networking Foundation
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

import org.apache.commons.lang.StringUtils;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.group.Group;
import org.onosproject.net.group.GroupBucket;
import org.onosproject.t3.api.StaticPacketTrace;

import java.util.List;

/**
 * Class containing utility methods for T3 cli.
 */
final class T3CliUtils {

    private T3CliUtils() {
        //banning construction
    }

    private static final String FLOW_SHORT_FORMAT = "    %s, bytes=%s, packets=%s, "
            + "table=%s, priority=%s, selector=%s, treatment=%s";

    private static final String GROUP_FORMAT =
            "   id=0x%s, state=%s, type=%s, bytes=%s, packets=%s, appId=%s, referenceCount=%s";
    private static final String GROUP_BUCKET_FORMAT =
            "       id=0x%s, bucket=%s, bytes=%s, packets=%s, actions=%s";

    public static final String NIB_AUTOFILLED =
            "*** NIB is invalid. Snapshots for the NIB have been auto-filled: ***";
    public static final String NIB_TERMINATE =
            "*** NIB is still invalid. You can manually load it via CLI commands for T3 load and try again ***";

    /**
     * Builds a string output for the given trace for a specific level of verbosity.
     *
     * @param trace      the trace
     * @param verbosity1 middle verbosity level
     * @param verbosity2 high verbosity level
     * @return a string representing the trace.
     */
    static String printTrace(StaticPacketTrace trace, boolean verbosity1, boolean verbosity2) {
        StringBuilder tracePrint = new StringBuilder();
        //Print based on verbosity
        if (verbosity1) {
            tracePrint = printTrace(trace, false, tracePrint);
        } else if (verbosity2) {
            tracePrint = printTrace(trace, true, tracePrint);
        } else {
            tracePrint.append("Paths");
            tracePrint.append("\n");
            List<List<ConnectPoint>> paths = trace.getCompletePaths();
            for (List<ConnectPoint> path : paths) {
                tracePrint.append(path);
                tracePrint.append("\n");
            }
        }
        tracePrint.append("Result: \n" + trace.resultMessage());
        return tracePrint.toString();
    }

    //prints the trace
    private static StringBuilder printTrace(StaticPacketTrace trace, boolean verbose, StringBuilder tracePrint) {
        List<List<ConnectPoint>> paths = trace.getCompletePaths();
        for (List<ConnectPoint> path : paths) {
            tracePrint.append("Path " + path);
            tracePrint.append("\n");
            ConnectPoint previous = null;
            if (path.size() == 1) {
                ConnectPoint connectPoint = path.get(0);
                tracePrint.append("Device " + connectPoint.deviceId());
                tracePrint.append("\n");
                tracePrint.append("Input from " + connectPoint);
                tracePrint.append("\n");
                tracePrint = printHitChains(trace, verbose, connectPoint.deviceId(), tracePrint);
                tracePrint.append("\n");
            } else {
                for (ConnectPoint connectPoint : path) {
                    if (previous == null || !previous.deviceId().equals(connectPoint.deviceId())) {
                        tracePrint.append("Device " + connectPoint.deviceId());
                        tracePrint.append("\n");
                        tracePrint.append("    Input from " + connectPoint);
                        tracePrint.append("\n");
                        tracePrint = printHitChains(trace, verbose, connectPoint.deviceId(), tracePrint);
                    }
                    previous = connectPoint;
                }
            }
            tracePrint.append(StringUtils.leftPad("\n", 100, '-'));
        }
        return tracePrint;
    }

    private static StringBuilder printHitChains(StaticPacketTrace trace, boolean verbose, DeviceId deviceId,
                                                        StringBuilder tracePrint) {
        tracePrint.append("    Hit chains ");
        tracePrint.append(trace.getHitChains(deviceId).size());
        tracePrint.append("    \n");
        tracePrint.append("    \n");
        int[] index = {1};
        trace.getHitChains(deviceId).forEach(hitChain -> {
            tracePrint.append("    Hit chain " + index[0]++);
            tracePrint.append("    \n");
            // Print for each chain the matchable entities first
            hitChain.getHitChain().forEach(dataPlaneEntity -> {
                if (dataPlaneEntity.getType() == DataPlaneEntity.Type.FLOWRULE) {
                    printFlow(dataPlaneEntity.getFlowEntry(), verbose, tracePrint);
                } else if (dataPlaneEntity.getType() == DataPlaneEntity.Type.GROUP) {
                    printGroup(dataPlaneEntity.getGroupEntry(), verbose, tracePrint);
                }
            });
            // Then the output packet of the current chain
            tracePrint.append("    Outgoing Packet " + hitChain.getEgressPacket());
            tracePrint.append("\n");
            // The output port of the current chain
            tracePrint.append("    Output through " + hitChain.getOutputPort());
            tracePrint.append("\n");
            // Dropped during the processing ?
            tracePrint.append("    Dropped " + hitChain.isDropped());
            tracePrint.append("\n");
            tracePrint.append("\n");
        });

        return tracePrint;
    }

    // Prints the flows for a given trace and a specified level of verbosity
    private static void printFlow(FlowEntry f, boolean verbose, StringBuilder tracePrint) {
        if (verbose) {
            tracePrint.append("    " + String.format(FLOW_SHORT_FORMAT, f.state(), f.bytes(), f.packets(),
                    f.table(), f.priority(), f.selector().criteria(),
                    printTreatment(f.treatment())));
        } else {
            tracePrint.append(String.format("       flowId=%s, table=%s, selector=%s", f.id(), f.table(),
                    f.selector().criteria()));
        }
        tracePrint.append("\n");
    }

    // Prints the groups for a given trace and a specified level of verbosity
    private static void printGroup(Group group, boolean verbose, StringBuilder tracePrint) {
        if (verbose) {
            tracePrint.append("    " + String.format(GROUP_FORMAT, Integer.toHexString(group.id().id()),
                    group.state(), group.type(), group.bytes(), group.packets(),
                    group.appId().name(), group.referenceCount()));
            tracePrint.append("\n");
            int i = 0;
            for (GroupBucket bucket : group.buckets().buckets()) {
                tracePrint.append("    " + String.format(GROUP_BUCKET_FORMAT,
                        Integer.toHexString(group.id().id()),
                        ++i, bucket.bytes(), bucket.packets(),
                        bucket.treatment().allInstructions()));
                tracePrint.append("\n");
            }
        } else {
            tracePrint.append("       groupId=" + group.id());
            tracePrint.append("\n");
        }
    }

    private static String printTreatment(TrafficTreatment treatment) {
        final String delimiter = ", ";
        StringBuilder builder = new StringBuilder("[");
        if (!treatment.immediate().isEmpty()) {
            builder.append("immediate=" + treatment.immediate() + delimiter);
        }
        if (!treatment.deferred().isEmpty()) {
            builder.append("deferred=" + treatment.deferred() + delimiter);
        }
        if (treatment.clearedDeferred()) {
            builder.append("clearDeferred" + delimiter);
        }
        if (treatment.tableTransition() != null) {
            builder.append("transition=" + treatment.tableTransition() + delimiter);
        }
        if (treatment.metered() != null) {
            builder.append("meter=" + treatment.metered() + delimiter);
        }
        if (treatment.writeMetadata() != null) {
            builder.append("metadata=" + treatment.writeMetadata() + delimiter);
        }
        // Chop off last delimiter
        builder.replace(builder.length() - delimiter.length(), builder.length(), "");
        builder.append("]");
        return builder.toString();
    }
}
