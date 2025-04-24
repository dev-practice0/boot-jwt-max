package org.example.bootjwtmax.auth;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {
    @Value("${jwt.secret}") // lombok value 아님!
    private String secretKey;
    @Value("${jwt.expiration-ms}")
    private long expirationMs;

    public SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    public String generateToken(Authentication authentication) { // 패러미터 -> 정보...
        String username = authentication.getName();
        Instant now = Instant.now(); // UTC.
        Date expiration = new Date(now.toEpochMilli() + expirationMs); // sql, <util>!!!!
        return Jwts.builder()
                .subject(username) // uuid를 넣어도 된다...
                .issuedAt(Date.from(now)) // 토큰생성일자
                .expiration(expiration) // 만료일자
                .signWith(getSecretKey(), Jwts.SIG.HS256) // 변환 알고리즘
                .compact();
    }

    public String getUsername(String token) {
        return Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)// // 1. 양식을 지켰나? 2. 키와 대응 3. 만료되었는가?
                .getPayload() // 유저 데이터
                .getSubject(); // username
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Authentication getAuthentication(String token) {
        UserDetails user = new User(getUsername(token), "", List.of());
        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    }
}
