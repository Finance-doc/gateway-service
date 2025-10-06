package com.financedoc.gateway_service.config;

import com.financedoc.gateway_service.jwt.JwtFilter;
import com.financedoc.gateway_service.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    @Order(0)
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable) // CSRF 비활성화
                .authorizeExchange(exchanges -> exchanges
                        // 인증이 필요없는 경로
                        .pathMatchers("/actuator/health", "/error", "/swagger-ui/**", "/v3/api-docs/**",
                                "/test-token", "/user/auth/kakao", "/user/auth/login", "/user/auth/refresh"
                        ).permitAll()
                        // 그외 필터에서 검증 후 X-User-Id 헤더가 없으면 차단
                        .anyExchange().authenticated()
                )
                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION) // JWT 검증 필터 적용
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable);

        return http.build();
    }
}
