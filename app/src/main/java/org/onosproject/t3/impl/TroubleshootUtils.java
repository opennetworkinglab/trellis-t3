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
import org.onosproject.net.ConnectPoint;
import org.onosproject.t3.api.StaticPacketTrace;

import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for the troubleshooting tool.
 */
final class TroubleshootUtils {

    private TroubleshootUtils() {
        //Banning construction
    }

    /**
     * Computes the list of traversed connect points.
     *
     * @param completePath the list of devices
     * @param trace        the trace we are building
     * @param output       the final output connect point
     * @return true only if the path is successfully computed and added to the trace
     */
    static boolean computePath(List<ConnectPoint> completePath, StaticPacketTrace trace, ConnectPoint output) {
        List<ConnectPoint> traverseList = new ArrayList<>();
        if (!completePath.contains(trace.getInitialConnectPoint())) {
            traverseList.add(trace.getInitialConnectPoint());
        }

        if (output != null && trace.getInitialConnectPoint().deviceId().equals(output.deviceId())) {
            trace.addCompletePath(ImmutableList.of(trace.getInitialConnectPoint(), output));
            return true;
        }

        traverseList.addAll(completePath);
        if (output != null && !completePath.contains(output)) {
            traverseList.add(output);
        }
        if (!trace.getCompletePaths().contains(traverseList)) {
            trace.addCompletePath(ImmutableList.copyOf(traverseList));
            return true;
        }
        return false;
    }

}
