/*
 * Copyright 2020-present Open Networking Foundation
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

package org.onosproject.t3.api;

import com.google.common.collect.ImmutableSet;
import org.onosproject.net.DeviceId;
import org.onosproject.net.group.Group;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represents Network Information Base (NIB) for groups
 * and supports alternative functions to
 * {@link org.onosproject.net.group.GroupService} for offline data.
 */
public class GroupNib extends AbstractNib {

    // TODO with method optimization, store into subdivided structures at the first load
    private Set<Group> groups;

    // use the singleton helper to create the instance
    protected GroupNib() {
    }

    /**
     * Sets a set of groups.
     *
     * @param groups group set
     */
    public void setGroups(Set<Group> groups) {
        this.groups = groups;
    }

    /**
     * Returns the set of groups.
     *
     * @return group set
     */
    public Set<Group> getGroups() {
        return ImmutableSet.copyOf(groups);
    }

    /**
     * Returns all groups associated with the given device and filtered by the group state.
     *
     * @param deviceId device ID to get groups for
     * @param groupState the group state
     * @return iterable of device's groups
     */
    public Iterable<Group> getGroupsByState(DeviceId deviceId, Group.GroupState groupState) {
        Set<Group> groupsFiltered = groups.stream()
                .filter(group -> group.state() == groupState
                        && group.deviceId().equals(deviceId))
                .collect(Collectors.toSet());
        return ImmutableSet.copyOf(groupsFiltered);
    }

    /**
     * Returns all groups associated with the given device.
     *
     * @param deviceId device ID to get groups for
     * @return iterable of device's groups
     */
    public Iterable<Group> getGroups(DeviceId deviceId) {
        Set<Group> groupsFiltered = groups.stream()
                .filter(group -> group.deviceId().equals(deviceId))
                .collect(Collectors.toSet());
        return ImmutableSet.copyOf(groupsFiltered);
    }

    /**
     * Returns the singleton instance of groups NIB.
     *
     * @return instance of groups NIB
     */
    public static GroupNib getInstance() {
        return GroupNib.SingletonHelper.INSTANCE;
    }

    private static class SingletonHelper {
        private static final GroupNib INSTANCE = new GroupNib();
    }

}
