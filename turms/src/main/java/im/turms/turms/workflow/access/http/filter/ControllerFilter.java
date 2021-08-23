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

package im.turms.turms.workflow.access.http.filter;

import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import im.turms.server.common.cluster.node.Node;
import im.turms.server.common.logging.RequestLoggingContext;
import im.turms.server.common.property.env.service.env.adminapi.LogProperties;
import im.turms.server.common.tracing.TracingCloseableContext;
import im.turms.server.common.tracing.TracingContext;
import im.turms.server.common.util.CollectionUtil;
import im.turms.turms.plugin.manager.TurmsPluginManager;
import im.turms.turms.workflow.access.http.performance.InefficientParam;
import im.turms.turms.workflow.access.http.permission.RequiredPermission;
import im.turms.turms.workflow.service.impl.admin.AdminService;
import im.turms.turms.workflow.service.impl.log.AdminActionLogService;
import org.springdoc.core.SpringDocConfigProperties;
import org.springdoc.webflux.api.OpenApiWebfluxResource;
import org.springdoc.webflux.ui.SwaggerWelcomeWebFlux;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.ConcurrentReferenceHashMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import javax.validation.constraints.NotNull;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.springframework.http.HttpHeaders.WWW_AUTHENTICATE;

/**
 * @author James Chen
 */
@Component
public class ControllerFilter implements WebFilter {

    private static final String BASIC_AUTH_PREFIX = "Basic ";
    private static final String ATTRIBUTES_ACCOUNT = "account";
    private static final BasicDBObject EMPTY_DBOJBECT = new BasicDBObject();
    private static final String ATTR_BODY = "BODY";

    private final Node node;
    private final RequestMappingHandlerMapping requestMappingHandlerMapping;
    private final AdminService adminService;
    private final AdminActionLogService adminActionLogService;
    private final TurmsPluginManager turmsPluginManager;
    private final boolean pluginEnabled;
    private final boolean enableAdminApi;
    private final boolean isOpenApiEnabled;

    private final Map<HandlerMethod, Api> apiCache = new ConcurrentReferenceHashMap<>(256);

    /**
     * @param springDocConfigProperties {@link org.springdoc.core.SpringDocConfiguration}
     */
    public ControllerFilter(
            Node node,
            RequestMappingHandlerMapping requestMappingHandlerMapping,
            AdminService adminService,
            AdminActionLogService adminActionLogService,
            TurmsPluginManager turmsPluginManager,
            @Autowired(required = false) SpringDocConfigProperties springDocConfigProperties) {
        this.requestMappingHandlerMapping = requestMappingHandlerMapping;
        this.adminService = adminService;
        this.adminActionLogService = adminActionLogService;
        this.node = node;
        this.turmsPluginManager = turmsPluginManager;
        pluginEnabled = node.getSharedProperties().getPlugin().isEnabled();
        enableAdminApi = node.getSharedProperties().getService().getAdminApi().isEnabled();
        isOpenApiEnabled = springDocConfigProperties != null && springDocConfigProperties.getApiDocs().isEnabled();


        DisposableServer server =
                HttpServer.create()
                        .handle((httpServerRequest, httpServerResponse) -> {
                            httpServerRequest.receive()
                        })
                        .route(routes ->
                                routes.route()
                                routes.get("/hello",
                                                (request, response) -> response.sendString(Mono.just("Hello World!")))
                                        .post("/echo",
                                                (request, response) -> response.send(request.receive().retain()))
                                        .get("/path/{param}",
                                                (request, response) -> response.sendString(Mono.just(request.param("param"))))
                                        .ws("/ws",
                                                (wsInbound, wsOutbound) -> wsOutbound.send(wsInbound.receive().retain())))
                        .bindNow();

        server.onDispose()
                .block();


    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        allowAnyRequest(exchange.getResponse());
        return requestMappingHandlerMapping.getHandler(exchange)
                .switchIfEmpty(Mono.defer(() -> filterUnhandledRequest(exchange, chain)))
                .flatMap(o -> {
                    if (o instanceof HandlerMethod method) {
                        return filterHandlerMethod(method, exchange, chain);
                    }
                    return filterUnhandledRequest(exchange, chain);
                });
    }

    private Api getApi(HandlerMethod handlerMethod) {
        return apiCache.computeIfAbsent(handlerMethod, method -> {
            RequiredPermission requiredPermission = method.getMethodAnnotation(RequiredPermission.class);
            Map<String, String[]> map = Collections.emptyMap();
            MethodParameter[] methodParameters = method.getMethodParameters();
            int paramCount = methodParameters.length;
            Set<String> params = paramCount == 0 ? Collections.emptySet() : CollectionUtil.newSet(paramCount);
            for (int i = 0; i < paramCount; i++) {
                MethodParameter parameter = methodParameters[i];
                params.add(parameter.getParameterName());
                InefficientParam param = parameter.getParameterAnnotation(InefficientParam.class);
                if (param != null) {
                    if (map.isEmpty()) {
                        map = new HashMap<>(16);
                    }
//                    map.put(parameter.getParameterName(), param.efficientCompanions());
                }
            }
            return new Api(requiredPermission, map, params);
        });
    }

    private Mono<Void> passOrRespondWith406IfInefficient(
            WebFilterChain chain,
            ServerWebExchange exchange,
            Api api) {
//        if (node.getSharedProperties().getService().getAdminApi().isAllowInefficientParams()) {
//            return chain.filter(exchange);
//        }
        MultiValueMap<String, String> params = exchange.getRequest().getQueryParams();
        for (Map.Entry<String, String[]> entry : api.illegalParams().entrySet()) {
            String inefficientParam = entry.getKey();
            if (params.containsKey(inefficientParam)) { // TODO: check value
                String[] companions = entry.getValue();
                int length = companions.length;
                String reason = null;
                if (length > 0) {
                    for (String companion : companions) {
                        if (!params.containsKey(companion)) {
                            reason = "The inefficient param \"" + inefficientParam
                                    + "\" should come with the params " + Arrays.toString(companions);
                            break;
                        }
                    }
                } else {
                    reason = "The inefficient param \"" + inefficientParam + "\" isn't allowed";
                }
                if (reason != null) {
                    return Mono.error(new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE,
                            reason));
                }
            }
        }
        return chain.filter(exchange);
    }

    private Mono<Void> filterHandlerMethod(HandlerMethod handlerMethod, ServerWebExchange exchange, WebFilterChain chain) {
        if (isOpenApiEnabledAndOpenApiRequest(handlerMethod)) {
            return chain.filter(exchange);
        }
        Api api = getApi(handlerMethod);
        RequiredPermission requiredPermission = api.permission();
        if (requiredPermission == null) {
            return passOrRespondWith406IfInefficient(chain, exchange, api);
        }
        if (!enableAdminApi) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return Mono.empty();
        }
        String[] credentials = parseAccountAndPassword(exchange);
        if (credentials == null) {
            return respondWith401(exchange.getResponse());
        }
        String account = credentials[0];
        String password = credentials[1];
        exchange.getAttributes().put(ATTRIBUTES_ACCOUNT, account);
        return adminService.authenticate(account, password)
                .flatMap(authenticated -> {
                    if (!authenticated) {
                        return respondWith401(exchange.getResponse());
                    }
                    return adminService.isAdminAuthorized(exchange, account, requiredPermission.value())
                            .flatMap(authorized -> authorized
                                    ? tryPersistAndPass(account, exchange, chain, handlerMethod, api)
                                    : respondWith401(exchange.getResponse()));
                });
    }

    /**
     * metrics APIs and swagger resources APIs don't have HandlerMethod instances
     */
    private Mono<Void> filterUnhandledRequest(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpResponse response = exchange.getResponse();
        if (CorsUtils.isPreFlightRequest(exchange.getRequest())) {
            response.setStatusCode(HttpStatus.OK);
            return Mono.empty();
        }
        if (!enableAdminApi) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return Mono.empty();
        }
        if (isOpenApiEnabledAndOpenApiRequest(exchange)) {
            return chain.filter(exchange);
        }
        String[] credentials = parseAccountAndPassword(exchange);
        if (credentials == null) {
            return respondWith401(response);
        }
        String account = credentials[0];
        String password = credentials[1];
        exchange.getAttributes().put(ATTRIBUTES_ACCOUNT, account);
        return adminService.authenticate(account, password)
                .flatMap(authenticated -> authenticated
                        ? chain.filter(exchange)
                        : respondWith401(response));
    }

    /**
     * 1. We don't expose configs for developers to customize the cors config
     * because it's better to be done by firewall/ECS/EC2
     * 2. Note that no only CORS requests but also some normal requests need these headers
     */
    private void allowAnyRequest(ServerHttpResponse response) {
        HttpHeaders headers = response.getHeaders();
        headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, "*");
        headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, "*");
        headers.set(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "7200");
    }

    private Mono<Void> respondWith401(ServerHttpResponse response) {
        response.getHeaders().set(WWW_AUTHENTICATE, "Basic realm=" + node.getNodeType().getDisplayName());
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return Mono.empty();
    }

    private String[] parseAccountAndPassword(@NotNull ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith(BASIC_AUTH_PREFIX)) {
            return null;
        }
        try {
            String encodedCredentials = authorization.substring(BASIC_AUTH_PREFIX.length());
            byte[] decode = Base64.getDecoder().decode(encodedCredentials);
            return StringUtils.split(new String(decode), ":");
        } catch (Exception e) {
            return null;
        }
    }

    private Mono<Void> tryPersistAndPass(
            String account,
            ServerWebExchange exchange,
            WebFilterChain chain,
            HandlerMethod handlerMethod,
            Api api) {
        LogProperties logProperties = node.getSharedProperties().getService().getAdminApi().getLog();
        boolean isLogEnabled = logProperties.isEnabled();
        boolean triggerHandlers = pluginEnabled && !turmsPluginManager.getAdminActionHandlerList().isEmpty();
        Mono<Void> additionalMono;
        if (isLogEnabled || triggerHandlers) {
            ServerHttpRequest request = exchange.getRequest();
            String action = handlerMethod.getMethod().getName();
            String host = Objects.requireNonNull(request.getRemoteAddress()).getHostString();
            MultiValueMap<String, String> params = logProperties.isLogRequestParams()
                    ? parseValidParams(request, api)
                    : null;
            Mono<BasicDBObject> bodyMono;
            if (logProperties.isLogRequestBody()) {
                bodyMono = parseValidBody(exchange);
                exchange = replaceRequestBody(exchange);
            } else {
                bodyMono = Mono.empty();
            }
            additionalMono = bodyMono.defaultIfEmpty(EMPTY_DBOJBECT).doOnNext(dbObject -> {
                DBObject body = dbObject != EMPTY_DBOJBECT ? dbObject : null;
                adminActionLogService.tryLogAndTriggerHandlers(
                        account,
                        new Date(),
                        host,
                        action,
                        params,
                        body);
            }).then();
        } else {
            additionalMono = Mono.empty();
        }
        ServerWebExchange finalExchange = exchange;
        TracingContext tracingContext = new TracingContext();
        return additionalMono
                .then(Mono.defer(() -> {
                    try (TracingCloseableContext ignored = tracingContext.asCloseable()) {
                        return passOrRespondWith406IfInefficient(chain, finalExchange, api);
                    }
                }))
                .contextWrite(context -> {
                    RequestLoggingContext loggingContext = new RequestLoggingContext(tracingContext);
                    finalExchange.getAttributes().put(RequestLoggingContext.CTX_KEY_NAME, loggingContext);
                    return context.put(RequestLoggingContext.CTX_KEY_NAME, loggingContext);
                })
                .doFinally(signalType -> finalExchange.getAttributes().remove(ATTR_BODY));
    }

    /**
     * Valid query params are the params requested by API
     */
    private MultiValueMap<String, String> parseValidParams(ServerHttpRequest request, Api api) {
        Set<String> methodParams = api.params();
        MultiValueMap<String, String> queryParams = request.getQueryParams();
        queryParams.keySet().removeIf(param -> !methodParams.contains(param));
        return queryParams;
    }

    private Mono<BasicDBObject> parseValidBody(@NotNull ServerWebExchange exchange) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .map(dataBuffer -> {
                    exchange.getAttributes().put(ATTR_BODY, dataBuffer);
                    String json = dataBuffer.toString(StandardCharsets.UTF_8);
                    BasicDBObject dbObject = BasicDBObject.parse(json);
                    return dbObject.isEmpty() ? EMPTY_DBOJBECT : dbObject;
                });
    }

    /**
     * Build a new request with a new body to pass down to RequestBodyMethodArgumentResolver.resolveArgument
     */
    private ServerWebExchange replaceRequestBody(ServerWebExchange exchange) {
        ServerHttpRequest mutatedRequest = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                DataBuffer dataBuffer = exchange.getAttribute(ATTR_BODY);
                if (dataBuffer != null) {
                    return Flux.just(dataBuffer);
                } else {
                    return getDelegate().getBody();
                }
            }
        };
        return exchange.mutate().request(mutatedRequest).build();
    }

    private boolean isOpenApiEnabledAndOpenApiRequest(HandlerMethod handlerMethod) {
        if (!isOpenApiEnabled) {
            return false;
        }
        Class<?> beanType = handlerMethod.getBeanType();
        return OpenApiWebfluxResource.class.equals(beanType) || SwaggerWelcomeWebFlux.class.equals(beanType);
    }

    private boolean isOpenApiEnabledAndOpenApiRequest(ServerWebExchange exchange) {
        return isOpenApiEnabled && exchange.getRequest().getURI().getPath().startsWith("/webjars/swagger-ui");
    }

}