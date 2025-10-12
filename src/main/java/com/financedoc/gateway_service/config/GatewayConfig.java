package com.financedoc.gateway_service.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {
    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("user-service", r -> r.path("/user/**")
                        .filters(f -> f
                                .removeRequestHeader("Cookie")
                                .filter((exchange, chain) -> {
                                    String userId = exchange.getRequest().getHeaders().getFirst("X-User-Id");
                                    if (userId != null) {
                                        exchange = exchange.mutate()
                                                .request(builderReq -> builderReq.header("X-User-Id", userId))
                                                .build();
                                    }
                                    return chain.filter(exchange);
                                })
                        )
                        .uri("http://user-service-service.default.svc.cluster.local:80"))
                .build();
    }
}
