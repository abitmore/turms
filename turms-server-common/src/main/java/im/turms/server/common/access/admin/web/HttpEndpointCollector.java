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

package im.turms.server.common.access.admin.web;

import im.turms.server.common.access.admin.permission.RequiredPermission;
import im.turms.server.common.access.admin.web.annotation.DeleteMapping;
import im.turms.server.common.access.admin.web.annotation.FormData;
import im.turms.server.common.access.admin.web.annotation.GetMapping;
import im.turms.server.common.access.admin.web.annotation.HeadMapping;
import im.turms.server.common.access.admin.web.annotation.PostMapping;
import im.turms.server.common.access.admin.web.annotation.PutMapping;
import im.turms.server.common.access.admin.web.annotation.QueryParam;
import im.turms.server.common.access.admin.web.annotation.RequestBody;
import im.turms.server.common.access.admin.web.annotation.RequestHeader;
import im.turms.server.common.access.admin.web.annotation.RestController;
import im.turms.server.common.infra.io.BaseFileResource;
import im.turms.server.common.infra.lang.Pair;
import im.turms.server.common.infra.lang.PrimitiveDefaultUtil;
import im.turms.server.common.infra.openapi.OpenApiBuilder;
import im.turms.server.common.infra.reflect.ReflectionUtil;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.HttpMethod;
import org.springframework.context.ConfigurableApplicationContext;

import javax.annotation.Nullable;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static im.turms.server.common.access.admin.web.MediaTypeConst.APPLICATION_JSON;
import static im.turms.server.common.access.admin.web.MediaTypeConst.APPLICATION_OCTET_STREAM;
import static im.turms.server.common.access.admin.web.MediaTypeConst.TEXT_PLAIN_UTF_8;

/**
 * @author James Chen
 */
public class HttpEndpointCollector {

    private HttpEndpointCollector() {
    }

    public static Map<ApiEndpointKey, ApiEndpoint> collectionEndpoints(ConfigurableApplicationContext context) {
        Map<ApiEndpointKey, ApiEndpoint> keyToEndpoint = new HashMap<>(256);
        Map<String, Object> beans = context.getBeansWithAnnotation(RestController.class);
        for (Object controller : beans.values()) {
            Class<?> controllerClass = controller.getClass();
            RestController annotation = controllerClass.getDeclaredAnnotation(RestController.class);
            String basePath = annotation.value();
            Method[] methods = controllerClass.getDeclaredMethods();
            for (Method method : methods) {
                ReflectionUtil.setAccessible(method);
                Pair<HttpMethod, String> methodAndPath = parseMethod(method);
                if (methodAndPath == null) {
                    continue;
                }
                String path = "/" + basePath;
                if (!methodAndPath.second().isBlank()) {
                    path += "/" + methodAndPath.second();
                }
                HttpMethod httpMethod = methodAndPath.first();
                String encoding = null;
                if (httpMethod == HttpMethod.GET) {
                    GetMapping mapping = method.getDeclaredAnnotation(GetMapping.class);
                    encoding = mapping.encoding().isBlank() ? null : mapping.encoding();
                }
                ApiEndpoint endpoint = new ApiEndpoint(controller,
                        method,
                        httpMethod,
                        parseParameters(method),
                        findMediaType(method),
                        encoding,
                        method.getDeclaredAnnotation(RequiredPermission.class));
                ApiEndpointKey key = new ApiEndpointKey(path, httpMethod);
                if (keyToEndpoint.containsKey(key)) {
                    throw new IllegalStateException("Duplicate endpoint: " + key + " in " + controllerClass.getName());
                }
                keyToEndpoint.put(key, endpoint);
            }
        }
        return keyToEndpoint;
    }

    private static String findMediaType(Method method) {
        Type type = OpenApiBuilder.unwrapType(method.getGenericReturnType());
        if (!(type instanceof Class<?> returnValueClass)) {
            return APPLICATION_JSON;
        }
        if (method.isAnnotationPresent(GetMapping.class)) {
            GetMapping mapping = method.getDeclaredAnnotation(GetMapping.class);
            if (!mapping.produces().isBlank()) {
                return mapping.produces();
            }
        }
        if (ByteBuf.class.isAssignableFrom(returnValueClass)
                || BaseFileResource.class.isAssignableFrom(returnValueClass)) {
            return APPLICATION_OCTET_STREAM;
        } else if (CharSequence.class.isAssignableFrom(returnValueClass)) {
            return TEXT_PLAIN_UTF_8;
        }
        return APPLICATION_JSON;
    }

    private static MethodParameterInfo[] parseParameters(Method method) {
        Parameter[] parameters = method.getParameters();
        MethodParameterInfo[] parameterInfos = new MethodParameterInfo[parameters.length];
        boolean hasRequestBody = false;
        boolean hasRequestFormData = false;
        for (int i = 0; i < parameters.length; i++) {
            Parameter parameter = parameters[i];
            MethodParameterInfo info = parseAsRequestBody(parameter);
            if (info != null) {
                parameterInfos[i] = info;
                if (hasRequestFormData) {
                    throw new IllegalArgumentException("The endpoint should not accept both request form data and request body");
                }
                hasRequestBody = true;
                continue;
            }
            info = parseAsRequestFormData(parameter);
            if (info != null) {
                parameterInfos[i] = info;
                if (hasRequestBody) {
                    throw new IllegalArgumentException("The endpoint should not accept both request form data and request body");
                }
                hasRequestFormData = true;
                continue;
            }
            info = parseAsRequestHeader(parameter);
            if (info != null) {
                parameterInfos[i] = info;
                continue;
            }
            if (RequestContext.class.isAssignableFrom(parameter.getType())) {
                parameterInfos[i] = new MethodParameterInfo(parameter.getName(),
                        RequestContext.class,
                        null,
                        false,
                        false,
                        false,
                        false,
                        null,
                        null);
                continue;
            }
            parameterInfos[i] = parseAsRequestParam(parameter);
        }
        return parameterInfos;
    }


    private static MethodParameterInfo parseAsRequestParam(Parameter parameter) {
        QueryParam queryParam = parameter.getDeclaredAnnotation(QueryParam.class);
        Class<?> type = parameter.getType();
        if (queryParam == null) {
            Object defaultValue = PrimitiveDefaultUtil.getDefaultValue(type);
            return new MethodParameterInfo(parameter.getName(),
                    type,
                    ReflectionUtil.getElementClass(parameter.getParameterizedType()),
                    defaultValue == null,
                    false,
                    false,
                    false,
                    defaultValue,
                    null);
        }
        String name = queryParam.value().isBlank() ? parameter.getName() : queryParam.value();
        Object parsedDefaultValue = queryParam.defaultValue().isBlank()
                ? PrimitiveDefaultUtil.getDefaultValue(type)
                : HttpRequestParamParser.parsePlainValue(queryParam.defaultValue(), type);
        return new MethodParameterInfo(name,
                type,
                ReflectionUtil.getElementClass(parameter.getParameterizedType()),
                queryParam.required(),
                false,
                false,
                false,
                parsedDefaultValue,
                null);
    }

    private static MethodParameterInfo parseAsRequestHeader(Parameter parameter) {
        RequestHeader requestHeader = parameter.getDeclaredAnnotation(RequestHeader.class);
        if (requestHeader == null) {
            return null;
        }
        String name = requestHeader.value().isBlank() ? parameter.getName() : requestHeader.value();
        Class<?> type = parameter.getType();
        return new MethodParameterInfo(name,
                type,
                ReflectionUtil.getElementClass(parameter.getParameterizedType()),
                requestHeader.required(),
                true,
                false,
                false,
                PrimitiveDefaultUtil.getDefaultValue(type),
                null);
    }

    private static MethodParameterInfo parseAsRequestBody(Parameter parameter) {
        RequestBody requestBody = parameter.getDeclaredAnnotation(RequestBody.class);
        if (requestBody == null) {
            return null;
        }
        return new MethodParameterInfo(parameter.getName(),
                parameter.getType(),
                ReflectionUtil.getElementClass(parameter.getParameterizedType()),
                requestBody.required(),
                false,
                true,
                false,
                null,
                null);
    }

    private static MethodParameterInfo parseAsRequestFormData(Parameter parameter) {
        FormData requestFormData = parameter.getDeclaredAnnotation(FormData.class);
        if (requestFormData == null) {
            return null;
        }
        if (!ReflectionUtil.isListOf(parameter.getParameterizedType(), MultipartFile.class)) {
            throw new IllegalArgumentException("The type of the form data parameter must be List<MultipartFile>: " + parameter);
        }
        String contentType = requestFormData.contentType();
        return new MethodParameterInfo(parameter.getName(),
                List.class,
                MultipartFile.class,
                requestFormData.required(),
                false,
                false,
                true,
                null,
                contentType.isBlank() ? null : contentType);
    }

    @Nullable
    private static Pair<HttpMethod, String> parseMethod(Method method) {
        if (method.isAnnotationPresent(GetMapping.class)) {
            return Pair.of(HttpMethod.GET, method.getDeclaredAnnotation(GetMapping.class).value());
        } else if (method.isAnnotationPresent(PostMapping.class)) {
            return Pair.of(HttpMethod.POST, method.getDeclaredAnnotation(PostMapping.class).value());
        } else if (method.isAnnotationPresent(PutMapping.class)) {
            return Pair.of(HttpMethod.PUT, method.getDeclaredAnnotation(PutMapping.class).value());
        } else if (method.isAnnotationPresent(DeleteMapping.class)) {
            return Pair.of(HttpMethod.DELETE, method.getDeclaredAnnotation(DeleteMapping.class).value());
        } else if (method.isAnnotationPresent(HeadMapping.class)) {
            return Pair.of(HttpMethod.HEAD, method.getDeclaredAnnotation(HeadMapping.class).value());
        }
        return null;
    }

}
