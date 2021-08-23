/*
 * Copyright (C) 2019 The Turms Project
 * https://github.com/turms-im/turms
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package im.turms.server.common.property.env.service.env.adminapi;

import com.fasterxml.jackson.annotation.JsonView;
import im.turms.server.common.property.metadata.annotation.Description;
import im.turms.server.common.property.metadata.annotation.GlobalProperty;
import im.turms.server.common.property.metadata.view.MutablePropertiesView;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author James Chen
 */
@AllArgsConstructor
@Builder(toBuilder = true)
@Data
@NoArgsConstructor
public class LogProperties {

    @Description("Whether to log API calls")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    private boolean enabled = true;

    @Description("Whether to log the parameters of requests")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    private boolean logRequestParams = true;

    @Description("Whether to log the body of requests. Better log the body of requests by monitor systems (e.g. Nginx, AWS)")
    @GlobalProperty
    @JsonView(MutablePropertiesView.class)
    private boolean logRequestBody;

}