package com.financedoc.gateway_service.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-token-validity}")
    private long accessTokenValidityMs;

    //객체 키 생성
    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(ensureBase64(secret));
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private String ensureBase64(String value) {
        if (value == null) return "";
        boolean looksBase64 = value.matches("^[A-Za-z0-9+/=]+={0,2}$");
        return looksBase64 ? value
                : Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(String userId, Map<String, Object> extraClaims) {
        Map<String, Object> claims = (extraClaims == null) ? new HashMap<>() : new HashMap<>(extraClaims);
        claims.putIfAbsent("user_id", userId);
        claims.put("category", "access");

        Date now = new Date();
        Date exp = new Date(now.getTime() + accessTokenValidityMs);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userId)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(secretKey)
                .compact();
    }

    public Claims parseClaims(String token) {
        return Jwts.parser()              // parserBuilder() 아님
                .verifyWith(secretKey)    // setSigningKey(...) 대신 verifyWith(Key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
