package org.example.bootjwtmax.controller;

import org.apache.coyote.BadRequestException;
import org.example.bootjwtmax.model.dto.TokenResponseDTO;
import org.example.bootjwtmax.model.dto.UserAccountRequestDTO;
import org.example.bootjwtmax.service.UserAccountService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController // REST API 컨트롤러임을 명시
@RequestMapping("/api/auth") // 기본 경로 지정
public class AuthController {
    private final UserAccountService userAccountService;

    // 생성자 주입 방식 (필드 초기화)
    public AuthController(UserAccountService userAccountService) {
        this.userAccountService = userAccountService;
    }

    // 로그인 API (POST /api/auth/login)
    @PostMapping("/login")
    public ResponseEntity<TokenResponseDTO> login(UserAccountRequestDTO dto) throws BadRequestException {
        TokenResponseDTO tokenResponseDTO = userAccountService.login(dto); // 로그인 처리 및 토큰 발급
        return ResponseEntity.ok(tokenResponseDTO); // 200 OK + 토큰 반환
    }

    // 회원가입 API (POST /api/auth/join)
    @PostMapping("/join")
    public ResponseEntity<Void> join(UserAccountRequestDTO dto) throws BadRequestException {
        userAccountService.join(dto); // 회원가입 처리
        return ResponseEntity.status(HttpStatus.CREATED).build(); // 201 Created 반환
    }

    // 어드민 회원가입 API (POST /api/auth/join2)
    @PostMapping("/join2")
    public ResponseEntity<Void> join2(UserAccountRequestDTO dto) throws BadRequestException {
        userAccountService.joinAdmin(dto); // 어드민 회원가입 처리
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    // 잘못된 요청 예외 처리
    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<String> badRequest(BadRequestException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    // 유저 없음 예외 처리
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<String> usernameNotFound(UsernameNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
    }

//    // 데이터 무결성 위반 예외 처리 (주석 처리됨)
//    @ExceptionHandler(DataIntegrityViolationException.class)
//    public ResponseEntity<String> dataIntegrityViolation(DataIntegrityViolationException ex) {
//        return ResponseEntity.status(HttpStatus.CONFLICT).body(ex.getMessage());
//    }
}
