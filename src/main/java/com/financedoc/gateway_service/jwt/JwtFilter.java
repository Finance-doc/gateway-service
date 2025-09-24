package com.financedoc.gateway_service.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtFilter implements GlobalFilter, Ordered {
    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.info("요청 들어옴: path={}", exchange.getRequest().getPath());

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        log.info("Authorization 헤더: {}", authHeader);

        if (authHeader == null) {
            log.warn("Authorization 없음 → 그냥 통과");
            return chain.filter(exchange);
        }
        if (!authHeader.startsWith("Bearer ")) {
            log.warn("Bearer 토큰 아님: {}", authHeader);
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);
        // 검증
        try {
            if (jwtUtil.isExpired(token)) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                log.error("만료된 토큰");
                return exchange.getResponse().setComplete();
            }
        } catch (Exception e) {
            log.error("JWT 검증 실패", e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // 사용자 정보 서비스에 헤더로 전달
        String email = jwtUtil.getEmail(token);
        log.info("JWT 인증 성공: email={}", email);

        // downstream 서비스에 헤더로 전달
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Email", email != null ? email : "")
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    @Override
    public int getOrder() {
        return -1; // 먼저 실행
    }
}
