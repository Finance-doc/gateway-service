package com.financedoc.gateway_service;

import com.financedoc.gateway_service.jwt.JwtUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtTestController {
    private final JwtUtil jwtUtil;

    public JwtTestController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/test-token")
    public String generateTestToken() {
        return jwtUtil.createAccess("test@example.com");
    }
}
