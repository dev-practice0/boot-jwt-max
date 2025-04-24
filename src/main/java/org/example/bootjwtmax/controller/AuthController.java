package org.example.bootjwtmax.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    // join, register
    @PostMapping("/join")
    public ResponseEntity<Void> join() {
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
