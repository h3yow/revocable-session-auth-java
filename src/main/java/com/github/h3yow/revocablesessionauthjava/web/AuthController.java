package com.github.h3yow.revocablesessionauthjava.web;

import com.github.h3yow.revocablesessionauthjava.domain.TokenPair;
import com.github.h3yow.revocablesessionauthjava.security.AuthService;
import com.github.h3yow.revocablesessionauthjava.web.dto.LoginRequest;
import com.github.h3yow.revocablesessionauthjava.web.dto.LogoutRequest;
import com.github.h3yow.revocablesessionauthjava.web.dto.RefreshRequest;
import com.github.h3yow.revocablesessionauthjava.web.dto.TokenResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 登录 / 刷新 / 注销。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        TokenPair pair = authService.login(request.username(), request.password());
        return TokenResponse.from(pair);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        TokenPair pair = authService.refresh(request.refreshToken());
        return TokenResponse.from(pair);
    }

    @PostMapping("/logout")
    public void logout(@RequestBody LogoutRequest request) {
        authService.logout(request.refreshToken());
    }
}
