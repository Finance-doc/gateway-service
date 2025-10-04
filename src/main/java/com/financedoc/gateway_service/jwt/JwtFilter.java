package com.financedoc.gateway_service.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
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

        // CORS 프리플라이트는 바로 통과
        HttpMethod method = exchange.getRequest().getMethod();
        if (method != null && HttpMethod.OPTIONS.equals(method)) {
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getPath().value();
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        log.info("[JwtFilter] 요청 path={}, Authorization={}", path, authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("[JwtFilter] Authorization 헤더 없음 또는 Bearer 형식 아님");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        String token = authHeader.substring(7);

        // 검증 및 식별자 추출
        try {
            Claims claims = jwtUtil.parseClaims(token);
            String userId = claims.getSubject();

            if (userId == null || userId.isBlank()) {
                log.warn("[JwtFilter] 토큰에 userId 없음: path={}", path);
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            // downstream 서비스에 헤더로 userId 전달
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-User-Id", userId)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (ExpiredJwtException e) {
            log.warn("[JwtFilter] JWT expired: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("[JwtFilter] JWT invalid: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("[JwtFilter] JWT unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("[JwtFilter] JWT illegal argument: {}", e.getMessage());
        } catch (Exception e) {
            log.error("[JwtFilter] JWT validation failed: {}", e.getMessage(), e);
        }
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1; // 먼저 실행
    }
}
