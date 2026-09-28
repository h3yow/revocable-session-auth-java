package com.github.h3yow.revocablesessionauthjava.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.revocablesessionauthjava.auth.TokenType;
import com.github.h3yow.revocablesessionauthjava.support.AuthTestLogger;
import com.github.h3yow.revocablesessionauthjava.support.TestClockConfig;
import com.github.h3yow.revocablesessionauthjava.token.TokenClaims;
import com.github.h3yow.revocablesessionauthjava.token.TokenService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 拆分后的失败归因在真实 HTTP 链路上各自落到稳定分类码，且响应体不泄露内部细节。
 * 借助 {@link TokenService} 以本服务密钥签发"签名合法但服务端登记对不上"的令牌，
 * 精确构造 session_token_mismatch 的各子情形。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClockConfig.class)
class FailureReasonApiTest {

    private static final Logger log = AuthTestLogger.logger(FailureReasonApiTest.class);

    @Autowired
    private MockMvc mvc;

    @Autowired
    private TokenService tokenService;

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("篡改/伪签名/结构非法/登记对不上：四种原因互不相同且稳定")
    void fourDistinctTokenReasons() throws Exception {
        JsonNode alice = login("alice", "alice123");
        String access = alice.get("accessToken").asText();

        // 1) 内容被改动：payload 翻转一字符，签名仍是 32 字节形态 -> tampered_token
        char flipped = access.charAt(0) == 'A' ? 'B' : 'A';
        String payloadTampered = flipped + access.substring(1);
        assertReason(payloadTampered, "tampered_token");
        AuthTestLogger.result(log, "payload 篡改 -> tampered_token");

        // 2) 签名对不上：合法 payload + 长度不符的伪造签名段 -> invalid_signature
        String bogusSig = access.substring(0, access.lastIndexOf('.') + 1) + "AAAAAAAAAAAAAAAAAAAA";
        assertReason(bogusSig, "invalid_signature");
        AuthTestLogger.result(log, "伪造签名 -> invalid_signature");

        // 3) 结构本身不合法 -> malformed_token
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer a.b.c"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("malformed_token"));
        AuthTestLogger.result(log, "三段结构 -> malformed_token");

        // 4a) 签名合法，但服务端没有这条会话登记 -> session_token_mismatch
        String unknownSession = sign(tokenService.issue("sess-never-existed", "alice", 0, TokenType.ACCESS));
        assertReason(unknownSession, "session_token_mismatch");
        AuthTestLogger.result(log, "令牌指向不存在会话 -> session_token_mismatch");

        // 4b) 签名合法、会话存在，但令牌主体与会话所有者对不上（挪用/拼接）-> session_token_mismatch
        MvcResult profile = mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk()).andReturn();
        String realSessionId = parse(profile).get("sessionId").asText();
        String wrongSubject = sign(tokenService.issue(realSessionId, "bob", 0, TokenType.ACCESS));
        assertReason(wrongSubject, "session_token_mismatch");
        AuthTestLogger.result(log, "令牌主体 != 会话所有者 -> session_token_mismatch");
    }

    @Test
    @DisplayName("刷新链路：服务端无此刷新令牌登记 -> session_token_mismatch")
    void unregisteredRefreshTokenMismatch() throws Exception {
        TokenClaims claims = tokenService.issue("sess-x", "alice", 0, TokenType.REFRESH);
        String raw = tokenService.sign(claims);
        MvcResult res = mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + raw + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_token_mismatch"))
                .andReturn();
        JsonNode body = parse(res);
        assertEquals(2, body.size());
        assertTrue(body.get("message").asText().contains("不一致"));
        AuthTestLogger.result(log, "未登记刷新令牌 -> 401 session_token_mismatch，响应仅 error/message");
    }

    private void assertReason(String accessToken, String expectedError) throws Exception {
        MvcResult res = mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value(expectedError))
                .andReturn();
        JsonNode body = parse(res);
        assertEquals(2, body.size(), "错误响应只能包含 error/message，不得带出内部细节");
        assertTrue(body.has("message"));
    }

    private String sign(TokenClaims claims) {
        return tokenService.sign(claims);
    }

    private JsonNode login(String username, String password) throws Exception {
        return parse(mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk()).andReturn());
    }

    private JsonNode parse(MvcResult res) throws Exception {
        return mapper.readTree(res.getResponse().getContentAsString());
    }
}
