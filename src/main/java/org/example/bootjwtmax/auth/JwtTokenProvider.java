package org.example.bootjwtmax.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

// 로그 출력용 어노테이션
@Component
@Log
public class JwtTokenProvider {
    // application.yml에서 jwt.secret 값을 읽어옴 (비밀키)
    @Value("${jwt.secret}")
    private String secretKey;
    // 토큰 만료 시간 (밀리초 단위)
    @Value("${jwt.expiration-ms}")
    private long expirationMs;

    // 비밀키를 SecretKey 객체로 변환 (JWT 라이브러리에서 사용)
    public SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    // JWT 토큰 생성 (인증 정보, 권한 리스트 전달)
    public String generateToken(Authentication authentication, List<String> roles) {
        String username = authentication.getName(); // 인증 객체에서 username 추출
        Instant now = Instant.now(); // 현재 시간 (UTC)
        Date expiration = new Date(now.toEpochMilli() + expirationMs); // 만료일 계산

        log.info("roles : %s".formatted(roles)); // 권한 로그 출력

        // JWT claims(토큰에 담을 정보) 생성
        Claims claims = Jwts.claims()
                .subject(username) // username을 subject로 설정
                .add("roles", roles) // roles를 추가 정보로 넣음
                .build();

        // JWT 토큰 생성 및 서명
        return Jwts.builder()
                .subject(username) // 토큰 주인
                .issuedAt(Date.from(now)) // 토큰 발급 시간
                .expiration(expiration) // 만료 시간
                .claims(claims) // claims 정보 추가
                .signWith(getSecretKey(), Jwts.SIG.HS256) // 비밀키로 서명(HS256 알고리즘)
                .compact(); // 최종 토큰 문자열 생성
    }

    // 토큰에서 username(subject) 추출
    public String getUsername(String token) {
        return Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    // 토큰 유효성 검사 (서명, 만료 등)
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token);
            return true; // 예외 없으면 유효
        } catch (JwtException | IllegalArgumentException e) {
            return false; // 예외 발생시 무효
        }
    }

    // 토큰에서 roles(권한) 정보 추출
    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        return (List<String>) Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("roles");
    }

    // 토큰에서 인증 객체(Authentication) 생성
    public Authentication getAuthentication(String token) {
        UserDetails user = new User(
                getUsername(token), // username
                "", // password는 필요없음
                getRoles(token).stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_%s".formatted(role))) // 권한 객체로 변환
                        .toList()
        );
        // 인증 객체 생성 (비밀번호는 null, 권한 포함)
        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    }
}
