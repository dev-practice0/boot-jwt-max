package org.example.bootjwtmax.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.example.bootjwtmax.model.entity.UserAccount;
import org.example.bootjwtmax.model.repository.UserAccountRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service // 서비스 빈 등록
@RequiredArgsConstructor // 생성자 자동 생성
@Log // 로그 사용
public class CustomUserDetailsService implements UserDetailsService {
    private final UserAccountRepository userAccountRepository;

    // username으로 회원 정보 조회
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // DB에서 회원 조회, 없으면 예외 발생
        UserAccount account = userAccountRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("유저가 없습니다. %s".formatted(username)));
        log.info("roles : %s".formatted(account.getRole())); // 권한 로그 출력
        // Spring Security User 객체로 변환
        return User.builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole()) // "USER", "ADMIN" 등
                .build();
    }
}
