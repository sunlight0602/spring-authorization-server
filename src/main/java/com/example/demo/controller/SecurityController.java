package com.example.demo.controller;

import lombok.AllArgsConstructor;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.ui.Model;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.AuthenticationException;

@RestController
@AllArgsConstructor
public class SecurityController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<MessageResponseDto> register(@RequestBody RegisterRequestDto request) {
        try {
            authenticationService.register(request.getUsername(), request.getPassword());
            return ResponseEntity.ok(new MessageResponseDto("註冊成功"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new MessageResponseDto("註冊失敗QQ"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDto request) {
        JwtResponseDto responseDto =
                authenticationService.login(request.getUsername(), request.getPassword());
        return ResponseEntity.ok(responseDto);
    }
}