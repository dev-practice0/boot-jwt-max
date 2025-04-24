package org.example.bootjwtmax.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.example.bootjwtmax.auth.JwtTokenProvider;
import org.example.bootjwtmax.model.entity.KakaoUser;
import org.example.bootjwtmax.model.repository.KakaoUserRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Log
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    private final KakaoUserRepository kakaoUserRepository;

    // 카카오 로그인 성공 시 사용자 정보 처리
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = delegate.loadUser(userRequest); // 카카오에서 사용자 정보 받아옴
        Map<String, Object> attributes = oAuth2User.getAttributes(); // 전체 응답 Map
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account"); // 계정 정보
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile"); // 프로필 정보
        String kakaoId = attributes.get("id").toString(); // 카카오 ID
        String nickname = profile.get("nickname").toString(); // 닉네임

        String username = "kakao_%s".formatted(kakaoId); // 내부 username 규칙

        // DB에 이미 있으면 조회, 없으면 신규 저장
        KakaoUser kakaoUser = kakaoUserRepository.findByUsername(username)
                .orElseGet(() -> {
                    KakaoUser newUser = new KakaoUser();
                    newUser.setUsername(username);
                    newUser.setName(nickname);
                    return kakaoUserRepository.save(newUser);
                });
        log.info(kakaoUser.toString());
        return oAuth2User; // 반환
    }

    // 소셜 로그인 성공 후 JWT 토큰 발급 및 응답
    @Service
    @RequiredArgsConstructor
    public static class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
        private final JwtTokenProvider jwtTokenProvider;

        @Override
        public void onAuthenticationSuccess(HttpServletRequest req,
                                            HttpServletResponse res,
                                            Authentication authentication) throws IOException, ServletException {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            String id = oAuth2User.getAttributes().get("id").toString();
            String username = "kakao_%s".formatted(id);
            String token = jwtTokenProvider.generateToken(
                    new UsernamePasswordAuthenticationToken(username, ""),
                    List.of("KAKAO")
            );
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, String> result = Map.of("token", token);
            res.setContentType("application/json;charset=UTF-8");
            res.getWriter().write(objectMapper.writeValueAsString(result));
        }
    }
}
