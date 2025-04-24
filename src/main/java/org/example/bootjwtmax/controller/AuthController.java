package org.example.bootjwtmax.controller;

import org.apache.coyote.BadRequestException;
import org.example.bootjwtmax.model.dto.UserAccountRequestDTO;
import org.example.bootjwtmax.service.UserAccountService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserAccountService userAccountService;

    public AuthController(UserAccountService userAccountService) {
        this.userAccountService = userAccountService;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(UserAccountRequestDTO dto) {
        return ResponseEntity.ok("");
    }

    // join, register
    @PostMapping("/join")
    public ResponseEntity<Void> join(UserAccountRequestDTO dto) throws BadRequestException {
        // 어떤 예외를 허용할 거냐?
        userAccountService.join(dto); // 실패하거나 검증상 문제가 생기면... throw...
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<String> badRequest(BadRequestException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

//    @ExceptionHandler(DataIntegrityViolationException.class)
//    public ResponseEntity<String> dataIntegrityViolation(DataIntegrityViolationException ex) {
//        return ResponseEntity.status(HttpStatus.CONFLICT).body(ex.getMessage());
//    }
}
