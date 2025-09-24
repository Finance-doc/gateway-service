package com.financedoc.gateway_service.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 10 * 60 * 1000; // 30분
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 60 * 60 * 1000; // 1시

    //객체 키 생성
    private final SecretKey secretKey;
    public JwtUtil() {
        // 임시 테스트 키 (나중에 @Value("${jwt.secret}") 로 교체)
        String secret = "my-test-secret-key-my-test-secret-key"; // 최소 256bit
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public Boolean isExpired(String token) {
        try {
            Claims claims = extractClaims(token);
            Date expiration = claims.getExpiration();

            if (expiration == null) {
                throw new RuntimeException(token + " has no expiration.");
            }

            return expiration.before(new Date());

        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            // 여기서 모든 검증 실패를 잡아서 다시 던짐
            throw new RuntimeException("유효하지 않은 JWT token", e);
        }
    }

    public String getEmail(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload()
                .get("email", String.class);
    }

    public String createAccess(String email) {
        return Jwts.builder()
                .claim("category", "access")
                .claim("email", email)
                .claim("role", "ROLE_MANAGER")
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRE_TIME))
                .signWith(secretKey)
                .compact();
    }

    public String createRefresh(String email) {
        return Jwts.builder()
                .claim("category", "refresh")
                .claim("email", email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRE_TIME))
                .signWith(secretKey)
                .compact();
    }

    private Claims extractClaims(String token){
        return Jwts.parser()
                .verifyWith(secretKey) // 서명검증
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }

    public String reIssueToken(String refreshToken){
        if (!isExpired(refreshToken)){
            return createAccess(getEmail(refreshToken));
        }
        throw new RuntimeException(refreshToken + "is expired.");
    }
}
