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

package im.turms.server.common.mongo.operation.option;

import im.turms.server.common.mongo.BsonPool;
import im.turms.server.common.util.MapUtil;
import lombok.Getter;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;

import javax.annotation.Nullable;

/**
 * @author James Chen
 * @implNote We don't use com.mongodb.internal.client.model.FindOptions
 * because it's really heavy
 */
@Getter
public final class QueryOptions {

    private static final BsonString COLLECTION_NAME_PLACEHOLDER = new BsonString("PLACEHOLDER");

    private final BsonDocument document;

    private QueryOptions(int expectedSize) {
        document = new BsonDocument(MapUtil.getCapability(expectedSize));
        document.put("find", COLLECTION_NAME_PLACEHOLDER);
    }

    public static QueryOptions newBuilder() {
        return new QueryOptions(4);
    }

    public static QueryOptions newBuilder(int expectedSize) {
        return new QueryOptions(expectedSize);
    }

    /**
     * @implNote We merge filter into query options so that we don't need to create two
     * documents and merge them later for better performance.
     * Filter count: 2
     */
    public BsonDocument asDocument(String collectionName, BsonDocument filter) {
        document.put("find", new BsonString(collectionName));
        document.put("filter", filter);
        return document;
    }

    /**
     * @implNote filter count: 1
     */
    public QueryOptions batchSize(int batchSize) {
        document.put("batchSize", new BsonInt32(batchSize));
        return this;
    }

    /**
     * @implNote filter count: 2
     */
    public QueryOptions max(String field) {
        document.put("limit", BsonPool.BSON_INT32_1);
        document.put("sort", new BsonDocument(field, BsonPool.BSON_INT32_NEGATIVE_1));
        return this;
    }

    /**
     * @implNote filter count: 2
     */
    public QueryOptions min(String field) {
        document.put("limit", BsonPool.BSON_INT32_1);
        document.put("sort", new BsonDocument(field, BsonPool.BSON_INT32_1));
        return this;
    }

    /**
     * @param page starts from 0
     * @implNote filter count: 2 or 0
     */
    public QueryOptions paginateIfNotNull(@Nullable Integer page, @Nullable Integer size) {
        if (size != null) {
            if (page == null) {
                page = 0;
            }
            document.put("skip", new BsonInt32(size * page));
            document.put("limit", new BsonInt32(size));
        }
        return this;
    }

    /**
     * @implNote filter count: 1
     */
    public QueryOptions sort(boolean asc, String field) {
        BsonInt32 value = asc
                ? BsonPool.BSON_INT32_1
                : BsonPool.BSON_INT32_NEGATIVE_1;
        document.put("sort", new BsonDocument(field, value));
        return this;
    }

    /**
     * @implNote filter count: 1
     */
    public QueryOptions include(String... fields) {
        BsonDocument projection = new BsonDocument();
        for (String field : fields) {
            projection.append(field, BsonPool.BSON_INT32_1);
        }
        document.put("projection", projection);
        return this;
    }

    /**
     * @implNote filter count: 1
     */
    public QueryOptions exclude(String... fields) {
        BsonDocument projection = new BsonDocument();
        for (String field : fields) {
            projection.append(field, BsonPool.BSON_INT32_0);
        }
        document.put("projection", projection);
        return this;
    }

    /**
     * @implNote filter count: 1
     */
    public QueryOptions limit(int limit) {
        document.put("limit", new BsonInt32(limit));
        return this;
    }

    /**
     * @implNote filter count: 1
     */
    public QueryOptions projection(BsonDocument projection) {
        document.put("projection", projection);
        return this;
    }

    /**
     * @implNote filter count: 1
     */
    public QueryOptions singleBatch() {
        document.put("singleBatch", BsonBoolean.TRUE);
        return this;
    }

}