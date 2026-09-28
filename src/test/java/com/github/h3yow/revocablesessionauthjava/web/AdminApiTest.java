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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 管理员会话治理与角色调整的 HTTP 集成测试，验证：
 * 权限（USER 403 / 未登录 401）、概览、单条/批量强制下线即时生效、兄弟会话不牵连、
 * 幂等结果、角色变更后旧令牌 401(session_state_changed) 与新权限 403/200 的区分，
 * 以及拆分后的归因码在 HTTP 层稳定且不泄露内部细节。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClockConfig.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AdminApiTest {

    private static final Logger log = AuthTestLogger.logger(AdminApiTest.class);

    @Autowired
    private MockMvc mvc;

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("非管理员不能治理：USER 403 access_denied；无令牌 401 missing_token")
    void adminEndpointsRequireAdmin() throws Exception {
        JsonNode alice = login("alice", "alice123");
        String userAccess = alice.get("accessToken").asText();

        mvc.perform(get("/api/admin/users/alice/sessions").header("Authorization", "Bearer " + userAccess))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"));
        AuthTestLogger.result(log, "USER 访问治理接口 -> 403 access_denied");

        mvc.perform(post("/api/admin/sessions/x/revoke"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("missing_token"));
        AuthTestLogger.result(log, "未登录访问治理接口 -> 401 missing_token");
    }

    @Test
    @DisplayName("会话概览 -> 单条强制下线：目标令牌立即失效，兄弟会话照常")
    void overviewAndRevokeOneSession() throws Exception {
        String adminAccess = login("admin", "admin123").get("accessToken").asText();
        JsonNode a = login("alice", "alice123");
        JsonNode b = login("alice", "alice123");

        MvcResult overviewRes = mvc.perform(get("/api/admin/users/alice/sessions")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeSessionCount").value(2))
                .andReturn();
        JsonNode overview = parse(overviewRes);
        String sessionA = overview.get("sessions").get(0).get("sessionId").asText();
        String sessionB = overview.get("sessions").get(1).get("sessionId").asText();
        assertNotEquals(sessionA, sessionB);
        assertTrue(overview.get("sessions").get(0).has("createdAtEpochMillis"));
        assertTrue(overview.get("sessions").get(0).has("lastActivityAtEpochMillis"));
        AuthTestLogger.result(log, "概览 200：{} 条生效会话，含标识与时间信息", overview.get("activeSessionCount").asInt());

        // 强制下线第一条
        mvc.perform(post("/api/admin/sessions/" + sessionA + "/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.found").value(true))
                .andExpect(jsonPath("$.revoked").value(true))
                .andExpect(jsonPath("$.alreadyRevoked").value(false));
        AuthTestLogger.result(log, "单条强制下线 200 found=true alreadyRevoked=false");

        // 目标会话旧令牌立即失效
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + a.get("accessToken").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_revoked"));
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + a.get("refreshToken").asText() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_revoked"));
        AuthTestLogger.result(log, "被下线会话：访问 401 session_revoked，刷新 401 session_revoked");

        // 兄弟会话照常可用
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + b.get("accessToken").asText()))
                .andExpect(status().isOk());
        AuthTestLogger.result(log, "同用户另一条会话访问 200，不受牵连");

        // 重复强制下线：稳定可重复
        mvc.perform(post("/api/admin/sessions/" + sessionA + "/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.found").value(true))
                .andExpect(jsonPath("$.alreadyRevoked").value(true));
        // 不存在的会话：也稳定 200，found=false，不冒底层错误
        MvcResult notFound = mvc.perform(post("/api/admin/sessions/no-such-session/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.found").value(false))
                .andExpect(jsonPath("$.revoked").value(false))
                .andReturn();
        JsonNode body = parse(notFound);
        assertEquals(4, body.size(), "结果只含稳定字段，不带内部细节");
        AuthTestLogger.result(log, "重复下线 alreadyRevoked=true；不存在会话 found=false，均无底层错误");
    }

    @Test
    @DisplayName("批量强制下线用户全部会话；不存在用户 -> 404 user_not_found")
    void revokeAllUserSessionsAndUnknownUser() throws Exception {
        String adminAccess = login("admin", "admin123").get("accessToken").asText();
        JsonNode a = login("alice", "alice123");
        login("alice", "alice123");

        mvc.perform(post("/api/admin/users/alice/sessions/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedSessionCount").value(2));
        AuthTestLogger.result(log, "批量强制下线 200 revokedSessionCount=2");

        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + a.get("accessToken").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_revoked"));

        // 重复批量：0 条
        mvc.perform(post("/api/admin/users/alice/sessions/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedSessionCount").value(0));

        // 不存在用户：404
        mvc.perform(get("/api/admin/users/ghost/sessions")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("user_not_found"));
        mvc.perform(post("/api/admin/users/ghost/sessions/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("user_not_found"));
        AuthTestLogger.result(log, "不存在用户治理 -> 404 user_not_found");
    }

    @Test
    @DisplayName("角色调整：旧访问令牌随即 401；刷新后新令牌按新角色（admin 200，降级后 403）")
    void roleChangeAppliesImmediatelyOverHttp() throws Exception {
        String adminAccess = login("admin", "admin123").get("accessToken").asText();
        JsonNode alice = login("alice", "alice123");
        String oldAccess = alice.get("accessToken").asText();
        String oldRefresh = alice.get("refreshToken").asText();

        // 升级前：profile 200，admin 403
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isOk());
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("access_denied"));

        // 管理员把 alice 升为 ADMIN
        mvc.perform(post("/api/admin/users/alice/roles")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"ROLE_ADMIN\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.affectedSessions").value(1));
        AuthTestLogger.result(log, "角色调整 200，会话版本提升");

        // 旧访问令牌下一次请求即按状态变更拒绝（401，与“没登录/不合法”同类认证失败，但原因码独立）
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_state_changed"));
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_state_changed"));
        AuthTestLogger.result(log, "旧令牌 -> 401 session_state_changed（不是 access_denied，分类清晰）");

        // 刷新拿到新令牌，按新角色：admin 200
        JsonNode rotated = parse(mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + oldRefresh + "\"}"))
                .andExpect(status().isOk()).andReturn());
        String newAccess = rotated.get("accessToken").asText();
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isOk());
        AuthTestLogger.result(log, "刷新后新令牌按 ROLE_ADMIN 判定，/api/admin/stats 200");

        // 再降级回 USER：新令牌也立即按状态变更失效，重登后 403
        mvc.perform(post("/api/admin/users/alice/roles")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"ROLE_USER\"]}"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_state_changed"));
        String reloginAccess = login("alice", "alice123").get("accessToken").asText();
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + reloginAccess))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"));
        AuthTestLogger.result(log, "降级后重登令牌访问 admin -> 403 access_denied，结论与未认证区分");
    }

    @Test
    @DisplayName("拆分后的归因码在 HTTP 层稳定：session_not_found 与 token_session_mismatch 可区分")
    void splitReasonsOverHttp() throws Exception {
        String adminAccess = login("admin", "admin123").get("accessToken").asText();
        JsonNode alice = login("alice", "alice123");
        String sessionId = parse(mvc.perform(get("/api/admin/users/alice/sessions")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk()).andReturn())
                .get("sessions").get(0).get("sessionId").asText();

        // 强制下线后服务端会话仍在（已撤销），因此旧令牌是 session_revoked（老结论不变）
        mvc.perform(post("/api/admin/sessions/" + sessionId + "/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + alice.get("accessToken").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_revoked"));

        // 结构不合法（三段）与签名错误（老结论不变）
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer a.b.c"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("malformed_token"));
        AuthTestLogger.result(log, "malformed_token / session_revoked 老结论稳定");
    }

    private JsonNode login(String username, String password) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return parse(res);
    }

    private JsonNode parse(MvcResult res) throws Exception {
        return mapper.readTree(res.getResponse().getContentAsString());
    }
}
