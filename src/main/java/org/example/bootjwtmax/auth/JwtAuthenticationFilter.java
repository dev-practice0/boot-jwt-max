package org.example.bootjwtmax.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 생성자 자동 생성 (JwtTokenProvider 필드 주입)
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // JWT 관련 기능을 제공하는 객체 (토큰 생성/검증/정보추출)
    private final JwtTokenProvider jwtTokenProvider;

    // 실제 필터 동작 메서드 (모든 HTTP 요청마다 실행)
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        // 1. 요청 헤더에서 Authorization 값을 가져옴
        String authHeader = req.getHeader("Authorization");
        // 2. 헤더가 있고, 'Bearer '로 시작하면 JWT 토큰이 있다고 판단
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // 3. 'Bearer ' 이후의 문자열(실제 토큰)만 추출
            String token = authHeader.substring(7);
            // 4. 토큰이 유효한지 확인
            if (jwtTokenProvider.validateToken(token)) {
                // 5. 토큰에서 인증 정보(Authentication 객체) 추출
                Authentication auth = jwtTokenProvider.getAuthentication(token);
                // 6. Spring Security의 인증 저장소에 등록 (이후 컨트롤러에서 인증정보 사용 가능)
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        // 7. 다음 필터(혹은 컨트롤러)로 요청을 넘김
        chain.doFilter(req, res);
    }
}
