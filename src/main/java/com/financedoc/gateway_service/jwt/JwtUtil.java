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
import java.util.Date;
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
        boolean looksBase64 = value.matches("^[A-Za-z0-9+/=]+$");
        if (!looksBase64) {
            return java.util.Base64.getEncoder().encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        return value;
    }

    public String createAccessToken(String subject, Map<String, Object> claims) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenValidityMs);
        return buildToken(subject, claims, now, expiry);
    }

    private String buildToken(String subject, Map<String, Object> claims, Date issuedAt, Date expiry) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .signWith(secretKey)
                .compact();
    }

    public Claims parseClaims(String token) {
        return Jwts.parser()              // ← parserBuilder()가 아니라 parser()
                .verifyWith(secretKey)    // ← setSigningKey(...) 대신 verifyWith(Key)
                .build()
                .parseSignedClaims(token) // ← parseClaimsJws(...) → parseSignedClaims(...)
                .getPayload();
    }
}
