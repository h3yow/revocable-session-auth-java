package com.github.h3yow.revocablesessionauthjava.auth;

import com.github.h3yow.revocablesessionauthjava.support.AuthAssertions;
import com.github.h3yow.revocablesessionauthjava.support.AuthTestLogger;
import com.github.h3yow.revocablesessionauthjava.support.TestClockConfig;
import com.github.h3yow.revocablesessionauthjava.token.TokenClaims;
import com.github.h3yow.revocablesessionauthjava.token.TokenService;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;

/**
 * 拆分后“令牌与服务端状态对不上”这一大类的领域测试：
 * <ul>
 *   <li>刷新令牌登记指向的会话与令牌声称会话不一致 -> TOKEN_SESSION_MISMATCH；</li>
 *   <li>令牌签名合法、jti 有登记，但登记的会话服务端已不存在 -> SESSION_NOT_FOUND；</li>
 *   <li>服务端完全没有该刷新令牌登记 -> UNKNOWN_TOKEN（老结论不变）。</li>
 * </ul>
 * 结构不合法与签名/篡改仍分别是 MALFORMED_TOKEN / INVALID_SIGNATURE（老结论不变，
 * 另由 {@code HmacTokenServiceTest} 与 {@code AuthServiceTest} 覆盖）。
 */
@SpringBootTest
@Import(TestClockConfig.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class FailureReasonSplitServiceTest {

    private static final Logger log = AuthTestLogger.logger(FailureReasonSplitServiceTest.class);

    @Autowired
    private AuthService authService;

    @Autowired
    private SessionStore sessionStore;

    @Autowired
    private TokenService tokenService;

    @Test
    @DisplayName("刷新令牌登记指向别的会话 -> TOKEN_SESSION_MISMATCH，而非 unknown/session_not_found")
    void refreshTokenBoundToDifferentSession() {
        TokenPair pair = authService.login("alice", "alice123");
        // 另建一条会话，把原刷新令牌登记改绑到它；令牌 claims.sessionId 仍是原会话
        TokenPair other = authService.login("alice", "alice123");
        String otherSessionId = authService.authenticateAccessToken(other.accessToken()).sessionId();

        TokenClaims claims = tokenService.parseAndVerify(pair.refreshToken(), TokenType.REFRESH);
        AuthTestLogger.input(log, "刷新令牌 jti={} 声称 sessionId={}，登记被改绑到 {}",
                claims.tokenId(), claims.sessionId(), otherSessionId);
        sessionStore.saveRefreshToken(
                new RefreshTokenRecord(claims.tokenId(), otherSessionId, claims.expiresAt()));

        AuthTestLogger.basis(log, "签名合法且 jti 有登记，但登记会话与令牌声称会话不一致");
        AuthAssertions.assertFailure(log, AuthFailureReason.TOKEN_SESSION_MISMATCH,
                () -> authService.refresh(pair.refreshToken()));
    }

    @Test
    @DisplayName("刷新路径：jti 有登记但会话已不存在 -> SESSION_NOT_FOUND（与 unknown_token 区分）")
    void refreshWithMissingSession() {
        TokenPair pair = authService.login("alice", "alice123");
        TokenClaims claims = tokenService.parseAndVerify(pair.refreshToken(), TokenType.REFRESH);
        AuthTestLogger.input(log, "保留刷新令牌登记 jti={}，登记指向一个不存在的会话", claims.tokenId());

        sessionStore.saveRefreshToken(
                new RefreshTokenRecord(claims.tokenId(), "sess-missing", claims.expiresAt()));
        AuthTestLogger.basis(log, "jti 有登记（不是 unknown_token），但登记会话查无此会话");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_NOT_FOUND,
                () -> authService.refresh(pair.refreshToken()));
    }

    @Test
    @DisplayName("服务端完全没有该刷新令牌登记 -> UNKNOWN_TOKEN（老分类结论不变）")
    void refreshTokenWithoutRegistration() {
        TokenClaims unregistered = tokenService.issue("sess-x", "alice", 0, TokenType.REFRESH);
        String compact = tokenService.sign(unregistered);
        AuthTestLogger.input(log, "自签合法刷新令牌但从不登记 jti={}", unregistered.tokenId());
        AuthTestLogger.basis(log, "签名/结构合法，jti 在存储中查不到 -> UNKNOWN_TOKEN");
        AuthAssertions.assertFailure(log, AuthFailureReason.UNKNOWN_TOKEN,
                () -> authService.refresh(compact));
    }

    @Test
    @DisplayName("访问路径：令牌合法但服务端无此会话 -> SESSION_NOT_FOUND")
    void accessWithMissingSession() {
        // 自签一个外形合法、其 sessionId 在存储中不存在的访问令牌
        TokenClaims ghost = tokenService.issue("sess-never-existed", "alice", 0, TokenType.ACCESS);
        String compact = tokenService.sign(ghost);
        AuthTestLogger.input(log, "自签合法访问令牌 sessionId=sess-never-existed，服务端无此会话");
        AuthTestLogger.basis(log, "签名/结构合法，回查会话为空 -> SESSION_NOT_FOUND");
        AuthAssertions.assertFailure(log, AuthFailureReason.SESSION_NOT_FOUND,
                () -> authService.authenticateAccessToken(compact));
    }
}
