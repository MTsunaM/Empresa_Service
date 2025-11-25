package com.microservicos.gatewayservice.Config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("cadastro-empresas", r -> r.path("/api/cadastroempresas")
                        .uri("http://localhost:8082"))
                .route("cadastro-goles",r -> r.path("/api/cadastrogolpes")
                        .uri("http://localhost:8081"))
                .route("auth-login", r -> r.path("/api/auth/**")
                        .uri("http://localhost:8082"))
                .build();

    }
}