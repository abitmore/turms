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

package im.turms.turms.workflow.dao.domain.group;

import im.turms.common.constant.GroupMemberRole;
import im.turms.server.common.mongo.entity.IndexType;
import im.turms.server.common.mongo.entity.ShardingStrategy;
import im.turms.server.common.mongo.entity.annotation.CompoundIndex;
import im.turms.server.common.mongo.entity.annotation.Document;
import im.turms.server.common.mongo.entity.annotation.Field;
import im.turms.server.common.mongo.entity.annotation.Id;
import im.turms.server.common.mongo.entity.annotation.Indexed;
import im.turms.server.common.mongo.entity.annotation.Sharded;
import im.turms.turms.workflow.dao.index.OptionalIndexedForExtendedFeature;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.PersistenceConstructor;

import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;
import java.util.Date;
import java.util.List;

/**
 * @author James Chen
 * @implNote Use compound index because it is frequently used by
 * isMemberMuted and queryGroupMemberRole
 */
@AllArgsConstructor(onConstructor = @__(@PersistenceConstructor))
@CompoundIndex({GroupMember.Fields.ID_GROUP_ID, GroupMember.Fields.ID_USER_ID})
@Data
@Document(GroupMember.COLLECTION_NAME)
@Sharded(shardKey = GroupMember.Fields.ID_GROUP_ID, shardingStrategy = ShardingStrategy.HASH)
public final class GroupMember {

    public static final String COLLECTION_NAME = "groupMember";

    @Id
    private final Key key;

    @Field(Fields.NAME)
    private final String name;

    @Field(Fields.ROLE)
    private final GroupMemberRole role;

    @Field(Fields.JOIN_DATE)
    @OptionalIndexedForExtendedFeature
    private final Date joinDate;

    @Field(Fields.MUTE_END_DATE)
    @OptionalIndexedForExtendedFeature
    private final Date muteEndDate;

    public GroupMember(
            @NotNull Long groupId,
            @NotNull Long userId,
            @Nullable String name,
            @NotNull GroupMemberRole role,
            @NotNull Date joinDate,
            @Nullable Date muteEndDate) {
        this.key = new Key(groupId, userId);
        this.name = name;
        this.role = role;
        this.joinDate = joinDate;
        this.muteEndDate = muteEndDate;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor // Make sure spring can initiate the key and use setters
    public static final class Key {

        @Field(Fields.GROUP_ID)
        private Long groupId;

        /**
         * Used by queryUsersJoinedGroupIds
         */
        @Field(Fields.USER_ID)
        @Indexed(IndexType.HASH)
        private Long userId;

        public static final class Fields {
            public static final String GROUP_ID = "gid";
            public static final String USER_ID = "uid";

            private Fields() {
            }
        }
    }

    public static final class Fields {
        public static final String ID_GROUP_ID = "_id." + Key.Fields.GROUP_ID;
        public static final String ID_USER_ID = "_id." + Key.Fields.USER_ID;
        public static final String NAME = "n";
        public static final String ROLE = "role";
        public static final String JOIN_DATE = "jd";
        public static final String MUTE_END_DATE = "med";

        private Fields() {
        }
    }

    @Data
    @AllArgsConstructor
    public static final class KeyList {
        private List<Key> keys;
    }
}