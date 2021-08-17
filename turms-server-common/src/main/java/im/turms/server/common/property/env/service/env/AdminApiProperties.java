/*
 * Copyright (C) 2019 The Turms Project
 * https://github.com/turms-im/turms
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package im.turms.server.common.property.env.service.env;

import com.fasterxml.jackson.annotation.JsonView;
import im.turms.server.common.property.env.common.AddressProperties;
import im.turms.server.common.property.metadata.annotation.Description;
import im.turms.server.common.property.metadata.annotation.GlobalProperty;
import im.turms.server.common.property.metadata.view.MutablePropertiesView;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import javax.validation.constraints.Min;

/**
 * @author James Chen
 */
@AllArgsConstructor
@Builder(toBuilder = true)
@Data
@NoArgsConstructor
public class AdminApiProperties {

    @Description("Whether to enable the APIs for administrators")
    @GlobalProperty
    private boolean enabled = true;

    @Description("Whether to allow administrators to delete data without any filter. " +
            "Better false to prevent administrators from deleting all data by accident")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    private boolean allowDeleteWithoutFilter;

    @Description("The allowed performance level for filters")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    private AllowedPerformanceLevel allowedPerformanceLevel = AllowedPerformanceLevel.PART_IXSCAN_PART_COLLSCAN;

    // FIXME: The property is unused
    @Description("The maximum day difference per query request")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    @Min(0)
    private int maxDayDifferencePerRequest = 3 * 30;

    @Description("The maximum hour difference per count request")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    @Min(0)
    private int maxHourDifferencePerCountRequest = 24;

    @Description("The maximum day difference per count request")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    @Min(0)
    private int maxDayDifferencePerCountRequest = 31;

    @Description("The maximum month difference per count request")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    @Min(0)
    private int maxMonthDifferencePerCountRequest = 12;

    @Description("The maximum available records per query request")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    @Min(0)
    private int maxAvailableRecordsPerRequest = 1000;

    // FIXME: The property is unused
    @Description("The maximum available online users' status per query request")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    @Min(0)
    private int maxAvailableOnlineUsersStatusPerRequest = 20;

    @Description("The default available records per query request")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    @Min(0)
    private int defaultAvailableRecordsPerRequest = 10;

    @JsonView(MutablePropertiesView.class)
    @NestedConfigurationProperty
    private AddressProperties address = new AddressProperties();

    public enum AllowedPerformanceLevel {
        /**
         * The filter uses only index scans or there is collection scans in a tiny collection
         * (usually less than 100 entries)
         */
        PART_IXSCAN_PART_TINY_COLLSCAN,
        /**
         * The filter uses both index scans and collection scans.
         * Most operations are allowed and the performance is acceptable in practice,
         */
        PART_IXSCAN_PART_COLLSCAN,
        /**
         * The filter uses only collection scans and there is no index scan.
         * All operations are allowed.
         * Only use the level if you know what you are doing.
         */
        ALL_COLLSCAN
    }
}