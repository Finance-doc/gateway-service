package com.financedoc.gateway_service;

import com.financedoc.gateway_service.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwtTestController {
    private final JwtUtil jwtUtil;

    @GetMapping("/test-token")
    public String generateTestToken() {
        // 테스트용 userId
        String testUserId = "testUserId";

        // 필요하면 claims를 넣을 수도 있음예시
        Map<String, Object> claims = Map.of("nickname", "TestUser's Nickname");

        return jwtUtil.createAccessToken(testUserId, claims);
    }
}
