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

package im.turms.turms.workflow.access.http.performance;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * If developers really need these features with efficient implementations,
 * they should implement the features according to their requirements and the solutions mentioned
 * in <a href="https://turms-im.github.io/docs/for-developers/schema.html">Schema Design</a>
 * To archive an efficient operation, inefficient params must come with efficient params
 * <p>
 * It usually means that they will query target data without using indexes in a lot of data
 *
 * @author James Chen
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface InefficientParam {
    /**
     * The param is efficient (uses index scan) if it comes with the params
     */
//    String[] efficientWithAll() default "";
//    String[] efficientWithAny() default "";
    String[] absoluteEfficientWith() default "";

    String[] efficientWith() default "";

    boolean efficientWithAny() default false;
//    String[] value();
}
