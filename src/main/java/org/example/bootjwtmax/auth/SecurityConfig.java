package org.example.bootjwtmax.auth;

import lombok.RequiredArgsConstructor;
import org.example.bootjwtmax.service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;

// 스프링 시큐리티 설정 클래스임을 명시
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {
    // 필요한 빈(객체)들을 주입받음
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOAuth2UserService.OAuth2LoginSuccessHandler successHandler;

    // 시큐리티 필터 체인 설정 (가장 중요)
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF(사이트간 요청 위조) 비활성화 (REST API에서 주로 사용)
                .csrf(AbstractHttpConfigurer::disable)
                // 세션을 사용하지 않음 (JWT 기반 인증)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 경로별 접근 권한 설정
                //순서에 유의 !!!
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll() // 인증 관련 경로는 모두 허용
                        .requestMatchers("/api/admin/**").hasRole("ADMIN") // 어드민만 접근 가능
                        .requestMatchers("/api/**").authenticated() // 나머지 /api 경로는 인증 필요
                        .anyRequest().permitAll() // 그 외는 모두 허용
                )
                // OAuth2(카카오 등) 소셜 로그인 설정
                .oauth2Login(oauth -> oauth
                        .userInfoEndpoint(user -> user.userService(customOAuth2UserService)) // 사용자 정보 처리 서비스 지정
                        .successHandler(successHandler) // 로그인 성공 후 처리 핸들러 지정
                )
                // DB 기반 인증 프로바이더 등록
                .authenticationProvider(daoAuthProvider())
                // JWT 인증 필터를 UsernamePasswordAuthenticationFilter 앞에 추가
                .addFilterBefore(jwtFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // 비밀번호 암호화 방식 설정 (BCrypt 등)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // DB 기반 인증 프로바이더 설정
    @Bean
    public DaoAuthenticationProvider daoAuthProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService); // 사용자 정보 서비스 지정
        authProvider.setPasswordEncoder(passwordEncoder()); // 비밀번호 인코더 지정
        return authProvider;
    }

    // JWT 인증 필터 빈 등록
    @Bean
    public JwtAuthenticationFilter jwtFilter() {
        return new JwtAuthenticationFilter(jwtTokenProvider);
    }

    // 인증 매니저 빈 등록 (여러 인증 프로바이더 관리)
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(daoAuthProvider()));
    }
}
