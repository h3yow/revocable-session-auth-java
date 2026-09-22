package com.github.h3yow.revocablesessionauthjava.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.revocablesessionauthjava.support.AuthTestLogger;
import com.github.h3yow.revocablesessionauthjava.support.TestClockConfig;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
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
 * HTTP 层集成测试：验证未认证/越权/撤销/轮换/并发在真实请求链路上的
 * 状态码与错误分类码一一对应，且响应体不泄露内部细节。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClockConfig.class)
class AuthApiTest {

    private static final Logger log = AuthTestLogger.logger(AuthApiTest.class);

    @Autowired
    private MockMvc mvc;

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("公开接口无需令牌；受保护接口缺令牌 -> 401 missing_token")
    void publicAndMissingToken() throws Exception {
        AuthTestLogger.input(log, "GET /api/public/ping 无令牌");
        mvc.perform(get("/api/public/ping"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"));
        AuthTestLogger.result(log, "SUCCESS 200，公开资源不拦截");

        AuthTestLogger.input(log, "GET /api/user/profile 无 Authorization 头");
        AuthTestLogger.basis(log, "拦截器：头缺失 -> MISSING_TOKEN -> 401");
        MvcResult res = mvc.perform(get("/api/user/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("missing_token"))
                .andReturn();
        assertNoInternalDetails(res);
        AuthTestLogger.result(log, "401 error=missing_token，响应体无内部细节");
    }

    @Test
    @DisplayName("伪造/篡改令牌 -> 401 invalid_signature；非 Bearer 头 -> 401 malformed_token")
    void forgedAndMalformedTokens() throws Exception {
        AuthTestLogger.input(log, "Authorization: Bearer garbage.token.here（三段结构）");
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer garbage.token.here"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("malformed_token"));
        AuthTestLogger.result(log, "结构不合法 -> 401 malformed_token");

        JsonNode login = login("alice", "alice123");
        String real = login.get("accessToken").asText();
        String forged = real.substring(0, real.lastIndexOf('.') + 1) + "AAAAAAAAAAAAAAAAAAAA";
        AuthTestLogger.input(log, "合法 payload + 伪造签名段");
        AuthTestLogger.basis(log, "结构合法但 HMAC 不匹配 -> INVALID_SIGNATURE");
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + forged))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_signature"));
        AuthTestLogger.result(log, "伪造签名 -> 401 invalid_signature");

        AuthTestLogger.input(log, "Authorization: Basic abc（错误方案）");
        mvc.perform(get("/api/user/profile").header("Authorization", "Basic abc"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("malformed_token"));
        AuthTestLogger.result(log, "非 Bearer 方案 -> 401 malformed_token");
    }

    @Test
    @DisplayName("登录 -> 访问受保护资源 -> 越权访问管理员接口 -> 403 access_denied")
    void loginAccessAndForbidden() throws Exception {
        JsonNode alice = login("alice", "alice123");
        String access = alice.get("accessToken").asText();
        AuthTestLogger.input(log, "alice 登录后 GET /api/user/profile");
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));
        AuthTestLogger.result(log, "SUCCESS 200，profile:read 命中");

        AuthTestLogger.input(log, "同一 alice 令牌 GET /api/admin/stats");
        AuthTestLogger.basis(log, "已认证但权限不足 -> ACCESS_DENIED -> 403（与未认证 401 可区分）");
        MvcResult res = mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"))
                .andReturn();
        assertNoInternalDetails(res);
        AuthTestLogger.result(log, "403 error=access_denied，越权与未认证结论不同");

        JsonNode admin = login("admin", "admin123");
        AuthTestLogger.input(log, "admin 登录后 GET /api/admin/stats");
        mvc.perform(get("/api/admin/stats")
                        .header("Authorization", "Bearer " + admin.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"));
        AuthTestLogger.result(log, "SUCCESS 200，通配权限命中");
    }

    @Test
    @DisplayName("HTTP 层刷新轮换：旧刷新令牌第二次使用 -> 401 refresh_token_reused")
    void refreshRotationOverHttp() throws Exception {
        JsonNode login = login("alice", "alice123");
        String refresh = login.get("refreshToken").asText();
        AuthTestLogger.input(log, "POST /api/auth/refresh 使用 refreshToken");

        JsonNode rotated = parse(mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isOk())
                .andReturn());
        assertNotEquals(refresh, rotated.get("refreshToken").asText());
        AuthTestLogger.result(log, "SUCCESS 200，签发新令牌对");

        AuthTestLogger.input(log, "再次提交同一旧 refreshToken");
        AuthTestLogger.basis(log, "服务端记录 used=true，CAS 失败");
        mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("refresh_token_reused"));
        AuthTestLogger.result(log, "401 error=refresh_token_reused");
    }

    @Test
    @DisplayName("HTTP 层并发刷新：仅一个 200，其余 401 refresh_token_reused")
    void concurrentRefreshOverHttp() throws Exception {
        JsonNode login = login("alice", "alice123");
        String refresh = login.get("refreshToken").asText();
        int threads = 6;
        AuthTestLogger.input(log, "同一 refreshToken 并发 POST /api/auth/refresh，线程数={}", threads);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger reused = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                start.await();
                MvcResult res = mvc.perform(post("/api/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"refreshToken\":\"" + refresh + "\"}"))
                        .andReturn();
                if (res.getResponse().getStatus() == 200) {
                    ok.incrementAndGet();
                } else {
                    JsonNode body = parse(res);
                    assertEquals("refresh_token_reused", body.get("error").asText());
                    reused.incrementAndGet();
                }
                return null;
            }));
        }
        ready.await();
        start.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        AuthTestLogger.basis(log, "CAS 单次抢占 + 错误分类码稳定");
        AuthTestLogger.result(log, "200 次数={} 401(reused) 次数={}", ok.get(), reused.get());
        assertEquals(1, ok.get());
        assertEquals(threads - 1, reused.get());
    }

    @Test
    @DisplayName("注销后访问：401 session_revoked；刷新同样被拒")
    void logoutThenAccessRevoked() throws Exception {
        JsonNode login = login("alice", "alice123");
        String access = login.get("accessToken").asText();
        String refresh = login.get("refreshToken").asText();

        mvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isOk());
        AuthTestLogger.result(log, "注销成功 200");

        AuthTestLogger.input(log, "注销后用旧 accessToken 访问 /api/user/profile");
        AuthTestLogger.basis(log, "实时回查会话 revoked=true，无缓存放行");
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_revoked"));
        AuthTestLogger.result(log, "401 error=session_revoked");

        AuthTestLogger.input(log, "注销后用旧 refreshToken 刷新");
        mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_revoked"));
        AuthTestLogger.result(log, "401 error=session_revoked");
    }

    @Test
    @DisplayName("错误凭据 -> 401 bad_credentials")
    void badCredentials() throws Exception {
        AuthTestLogger.input(log, "POST /api/auth/login alice/wrong-password");
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"wrong-password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("bad_credentials"));
        AuthTestLogger.result(log, "401 error=bad_credentials");
    }

    private JsonNode login(String username, String password) throws Exception {
        AuthTestLogger.input(log, "POST /api/auth/login username={}", username);
        MvcResult res = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = parse(res);
        assertTrue(body.has("accessToken") && body.has("refreshToken"));
        AuthTestLogger.result(log, "登录成功，获得令牌对");
        return body;
    }

    private JsonNode parse(MvcResult res) throws Exception {
        return mapper.readTree(res.getResponse().getContentAsString());
    }

    /** 响应体只允许 error/message 两个字段，确保不泄露堆栈或内部标识。 */
    private void assertNoInternalDetails(MvcResult res) throws Exception {
        JsonNode body = parse(res);
        assertEquals(2, body.size(), "错误响应只能包含 error/message 字段");
        assertTrue(body.has("error") && body.has("message"));
    }
}
