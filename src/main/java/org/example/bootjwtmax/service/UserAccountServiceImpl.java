package org.example.bootjwtmax.service;

import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.example.bootjwtmax.auth.JwtTokenProvider;
import org.example.bootjwtmax.model.dto.TokenResponseDTO;
import org.example.bootjwtmax.model.dto.UserAccountRequestDTO;
import org.example.bootjwtmax.model.entity.UserAccount;
import org.example.bootjwtmax.model.repository.UserAccountRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserAccountServiceImpl implements UserAccountService {
    private final UserAccountRepository userAccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    // 일반 회원가입
    @Override
    public void join(UserAccountRequestDTO dto) throws BadRequestException {
        if (dto.username().isEmpty() || dto.password().isEmpty()) {
            throw new BadRequestException("비어 있는 항목이 있습니다");
        }
        UserAccount userAccount = new UserAccount();
        userAccount.setUsername(dto.username());
        userAccount.setPassword(passwordEncoder.encode(dto.password())); // 비밀번호 암호화
        userAccount.setRole("USER"); // 권한 지정
        try {
            userAccountRepository.save(userAccount); // DB 저장
        } catch (DataIntegrityViolationException ex) {
            throw new BadRequestException("중복된 Username");
        }
    }

    // 로그인
    @Override
    public TokenResponseDTO login(UserAccountRequestDTO dto) throws BadRequestException, UsernameNotFoundException {
        if (dto.username().isEmpty() || dto.password().isEmpty()) {
            throw new BadRequestException("비어 있는 항목이 있습니다");
        }
        if (userAccountRepository.findByUsername(dto.username()).isEmpty()) {
            throw new UsernameNotFoundException(("없는 유저입니다"));
        }
        // 인증 처리 (비밀번호 검증)
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.username(), dto.password())
        );
        UserAccount account = userAccountRepository.findByUsername(dto.username()).orElseThrow();
        // JWT 토큰 발급
        String token = jwtTokenProvider.generateToken(authentication, List.of(account.getRole()));
        return new TokenResponseDTO(token);
    }

    // 어드민 회원가입
    @Override
    public void joinAdmin(UserAccountRequestDTO dto) throws BadRequestException {
        if (dto.username().isEmpty() || dto.password().isEmpty()) {
            throw new BadRequestException("비어 있는 항목이 있습니다");
        }
        UserAccount userAccount = new UserAccount();
        userAccount.setUsername(dto.username());
        userAccount.setPassword(passwordEncoder.encode(dto.password()));
        userAccount.setRole("ADMIN"); // 어드민 권한
        try {
            userAccountRepository.save(userAccount);
        } catch (DataIntegrityViolationException ex) {
            throw new BadRequestException("중복된 Username");
        }
    }
}
