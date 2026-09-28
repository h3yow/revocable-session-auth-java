package com.github.h3yow.revocablesessionauthjava.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 管理员会话治理 / 角色调整的 HTTP 集成测试，并覆盖拆分后的失败归因在真实链路上的分类码。
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClockConfig.class)
class AdminApiTest {

    private static final Logger log = AuthTestLogger.logger(AdminApiTest.class);

    @Autowired
    private MockMvc mvc;

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("治理接口鉴权：无令牌 401 missing_token；普通用户 403 access_denied；admin 200")
    void adminEndpointsRequireAdmin() throws Exception {
        AuthTestLogger.input(log, "无令牌 GET /api/admin/users/alice/sessions");
        mvc.perform(get("/api/admin/users/alice/sessions"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("missing_token"));

        JsonNode alice = login("alice", "alice123");
        String userAccess = alice.get("accessToken").asText();
        AuthTestLogger.input(log, "alice(USER) 访问治理接口");
        MvcResult denied = mvc.perform(get("/api/admin/users/alice/sessions")
                        .header("Authorization", "Bearer " + userAccess))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"))
                .andReturn();
        assertOnlyErrorAndMessage(denied);
        AuthTestLogger.result(log, "未登录=401、登录但权限不够=403，结论清晰可分");

        JsonNode admin = login("admin", "admin123");
        mvc.perform(get("/api/admin/users/alice/sessions")
                        .header("Authorization", "Bearer " + admin.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));
        AuthTestLogger.result(log, "admin 200");
    }

    @Test
    @DisplayName("会话概览 + 强制下线单条：旧令牌立即失效，另一条会话不受影响")
    void listAndRevokeOneSessionOverHttp() throws Exception {
        String adminAccess = login("admin", "admin123").get("accessToken").asText();
        JsonNode s1 = login("alice", "alice123");
        JsonNode s2 = login("alice", "alice123");
        String access1 = s1.get("accessToken").asText();
        String refresh1 = s1.get("refreshToken").asText();

        // 先让两条会话各活动一次，便于观察 lastActiveAtEpochMillis
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + access1)).andExpect(status().isOk());
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + s2.get("accessToken").asText()))
                .andExpect(status().isOk());

        MvcResult listRes = mvc.perform(get("/api/admin/users/alice/sessions")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode list = parse(listRes);
        AuthTestLogger.input(log, "admin 查询 alice 会话概览 activeSessionCount={}", list.get("activeSessionCount").asInt());
        assertTrue(list.get("activeSessionCount").asInt() >= 2);
        String sessionId1 = profile(access1).get("sessionId").asText();
        JsonNode entry = findSession(list, sessionId1);
        assertTrue(entry.has("sessionId") && entry.has("createdAtEpochMillis")
                && entry.has("lastActiveAtEpochMillis"));
        assertTrue(entry.get("lastActiveAtEpochMillis").asLong() >= entry.get("createdAtEpochMillis").asLong());
        AuthTestLogger.result(log, "概览含标识/创建时间/最近活动时间");

        mvc.perform(post("/api/admin/sessions/" + sessionId1 + "/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"));
        AuthTestLogger.result(log, "强制下线 sessionId={}", sessionId1);

        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + access1))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_revoked"));
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh1 + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_revoked"));
        AuthTestLogger.result(log, "被下线会话的访问/刷新立即 401 session_revoked");

        // 另一条会话不受牵连
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + s2.get("accessToken").asText()))
                .andExpect(status().isOk());
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + s2.get("refreshToken").asText() + "\"}"))
                .andExpect(status().isOk());
        AuthTestLogger.result(log, "同用户另一条会话访问/刷新照常 200");

        // 不存在 / 重复下线：稳定结论
        mvc.perform(post("/api/admin/sessions/no-such-session/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("not_found"));
        mvc.perform(post("/api/admin/sessions/" + sessionId1 + "/revoke")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"));
        AuthTestLogger.result(log, "不存在=not_found，重复下线仍稳定 revoked，无底层错误");
    }

    @Test
    @DisplayName("强制下线用户全部会话：该用户全部令牌失效；其他用户不受影响")
    void revokeAllSessionsOverHttp() throws Exception {
        String adminAccess = login("admin", "admin123").get("accessToken").asText();
        JsonNode a1 = login("alice", "alice123");
        JsonNode a2 = login("alice", "alice123");
        JsonNode bob = login("admin", "admin123"); // 另一用户（admin 账户）

        mvc.perform(post("/api/admin/users/alice/sessions/revoke-all")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"))
                .andExpect(jsonPath("$.revokedSessionCount").isNumber());
        AuthTestLogger.result(log, "alice 全部会话已下线");

        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + a1.get("accessToken").asText()))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("session_revoked"));
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + a2.get("accessToken").asText()))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("session_revoked"));
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + bob.get("accessToken").asText()))
                .andExpect(status().isOk());
        AuthTestLogger.result(log, "alice 全部 401 session_revoked，其他用户 200 不受牵连");
    }

    @Test
    @DisplayName("角色调整走 Web 接口：旧访问令牌立即 session_state_changed，刷新/重登后按新角色判定")
    void roleChangeOverHttpTakesEffectImmediately() throws Exception {
        String adminAccess = login("admin", "admin123").get("accessToken").asText();
        JsonNode alice = login("alice", "alice123");
        String oldAccess = alice.get("accessToken").asText();
        String oldRefresh = alice.get("refreshToken").asText();

        // 变更前：能访问 profile，不能访问 stats
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isOk());
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("access_denied"));

        mvc.perform(post("/api/admin/users/alice/roles")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"ROLE_ADMIN\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountFound").value(true))
                .andExpect(jsonPath("$.status").value("updated"));
        AuthTestLogger.result(log, "角色已调整 alice -> ROLE_ADMIN");

        // 旧访问令牌：版本不符 -> 401（不是 403，也不是放行）
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_state_changed"));
        AuthTestLogger.result(log, "旧令牌下次请求即 401 session_state_changed");

        // 刷新拿到新令牌：按新角色判定，stats 200
        JsonNode rotated = parse(mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + oldRefresh + "\"}"))
                .andExpect(status().isOk()).andReturn());
        String newAccess = rotated.get("accessToken").asText();
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isOk());
        AuthTestLogger.result(log, "刷新后新令牌按 ROLE_ADMIN 放行 admin:stats");

        // 降回 USER：新令牌立即失去 admin 权限
        mvc.perform(post("/api/admin/users/alice/roles")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"ROLE_USER\"]}"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_state_changed"));
        JsonNode reLogin = login("alice", "alice123");
        mvc.perform(get("/api/admin/stats")
                        .header("Authorization", "Bearer " + reLogin.get("accessToken").asText()))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("access_denied"));
        AuthTestLogger.result(log, "降权后旧令牌 401，重登新令牌 403 access_denied");

        // 不存在的用户：稳定空操作
        mvc.perform(post("/api/admin/users/ghost/roles")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"roles\":[]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountFound").value(false))
                .andExpect(jsonPath("$.status").value("user_not_found"));
    }

    @Test
    @DisplayName("拆分后的失败归因在 HTTP 链路上的分类由 FailureReasonApiTest 覆盖；本用例验证篡改仍稳定落类")
    void tamperedTokenStillRejectedOverHttp() throws Exception {
        JsonNode alice = login("alice", "alice123");
        String access = alice.get("accessToken").asText();
        char flipped = access.charAt(0) == 'A' ? 'B' : 'A';
        String payloadTampered = flipped + access.substring(1);
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + payloadTampered))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("tampered_token"));
        AuthTestLogger.result(log, "payload 篡改 -> 401 tampered_token");
    }

    private JsonNode findSession(JsonNode list, String sessionId) {
        for (JsonNode node : list.get("sessions")) {
            if (sessionId.equals(node.get("sessionId").asText())) {
                return node;
            }
        }
        throw new AssertionError("概览中缺少会话 " + sessionId);
    }

    private JsonNode profile(String accessToken) throws Exception {
        return parse(mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk()).andReturn());
    }

    private JsonNode login(String username, String password) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk()).andReturn();
        return parse(res);
    }

    private JsonNode parse(MvcResult res) throws Exception {
        return mapper.readTree(res.getResponse().getContentAsString());
    }

    private void assertOnlyErrorAndMessage(MvcResult res) throws Exception {
        JsonNode body = parse(res);
        assertEquals(2, body.size(), "错误响应只能包含 error/message");
        assertTrue(body.has("error") && body.has("message"));
    }
}
