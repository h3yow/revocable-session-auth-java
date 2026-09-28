package com.github.h3yow.revocablesessionauthjava.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.revocablesessionauthjava.auth.Permissions;
import com.github.h3yow.revocablesessionauthjava.support.AuthTestLogger;
import com.github.h3yow.revocablesessionauthjava.support.TestClockConfig;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
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
 * 管理员治理接口 HTTP 集成测试：会话概览 / 单条 / 全部强制下线 / 角色调整，
 * 覆盖权限（401 vs 403）、404 稳定原因、幂等结果与篡改令牌的线上分类。
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
    @DisplayName("未带令牌 -> 401 missing_token；普通用户调治理接口 -> 403 access_denied")
    void adminEndpointAuthnAndAuthz() throws Exception {
        mvc.perform(get("/api/admin/users/alice/sessions"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("missing_token"));

        setRoles("alice", Set.of(Permissions.ROLE_USER));
        JsonNode alice = login("alice", "alice123");
        AuthTestLogger.basis(log, "alice(ROLE_USER) 访问需 admin:sessions 的接口");
        mvc.perform(get("/api/admin/users/alice/sessions")
                        .header("Authorization", "Bearer " + alice.get("accessToken").asText()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"));
        AuthTestLogger.result(log, "401(未登录) 与 403(权限不足) 结论清晰可分");
    }

    @Test
    @DisplayName("会话概览 -> 强制下线单条：该会话令牌立即失效，另一条照常；不存在会话 404；重复下线幂等")
    void listAndRevokeOneSessionOverHttp() throws Exception {
        String admin = adminToken();
        JsonNode s1 = login("alice", "alice123");
        JsonNode s2 = login("alice", "alice123");

        // 用每个访问令牌访问 profile，响应体里的 sessionId 用来确定性地映射令牌->会话
        String access1 = s1.get("accessToken").asText();
        String access2 = s2.get("accessToken").asText();
        String id1 = profileSessionId(access1);
        String id2 = profileSessionId(access2);
        org.junit.jupiter.api.Assertions.assertNotEquals(id1, id2);

        JsonNode overview = listSessions(admin, "alice");
        Set<String> now = sessionIds(overview);
        assertTrue(now.contains(id1) && now.contains(id2), "概览应包含两条新会话");
        for (JsonNode item : overview.get("sessions")) {
            assertTrue(item.has("sessionId") && item.has("createdAtEpochMillis")
                    && item.has("lastActiveAtEpochMillis"));
        }
        AuthTestLogger.result(log, "管理员看到会话及稳定概览字段 activeCount={}",
                overview.get("activeSessionCount").asInt());

        // 强制下线 id1
        mvc.perform(post("/api/admin/sessions/" + id1 + "/revoke")
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"));
        AuthTestLogger.result(log, "单条强制下线 200 sessionId={}", id1);

        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + access1))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_revoked"));
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + access2))
                .andExpect(status().isOk());
        AuthTestLogger.result(log, "被下线会话令牌立即失效，同用户另一条照常 200");

        // 重复下线同一条：幂等成功
        mvc.perform(post("/api/admin/sessions/" + id1 + "/revoke")
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"));
        // 不存在会话：稳定 404 session_not_found
        MvcResult notFound = mvc.perform(post("/api/admin/sessions/sess-ghost/revoke")
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("session_not_found"))
                .andReturn();
        assertOnlyErrorFields(notFound);
        AuthTestLogger.result(log, "重复下线幂等；不存在会话稳定 404 session_not_found");
    }

    @Test
    @DisplayName("全部强制下线：该用户令牌全部失效，其他用户不受影响；重复调用计数 0")
    void revokeAllSessionsOverHttp() throws Exception {
        String admin = adminToken();
        login("alice", "alice123");
        login("alice", "alice123");
        JsonNode otherUser = login("admin", "admin123");

        int activeBefore = listSessions(admin, "alice").get("activeSessionCount").asInt();
        assertTrue(activeBefore >= 2);
        MvcResult res = mvc.perform(post("/api/admin/users/alice/sessions/revoke")
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("revoked"))
                .andExpect(jsonPath("$.revokedSessionCount").value(activeBefore))
                .andReturn();
        AuthTestLogger.result(log, "全部下线 {} 条, body={}", activeBefore, res.getResponse().getContentAsString());

        assertEquals(0, listSessions(admin, "alice").get("activeSessionCount").asInt());
        mvc.perform(post("/api/admin/users/alice/sessions/revoke")
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedSessionCount").value(0));
        mvc.perform(get("/api/admin/stats")
                        .header("Authorization", "Bearer " + otherUser.get("accessToken").asText()))
                .andExpect(status().isOk());
        AuthTestLogger.result(log, "重复下线计数 0；其他用户(admin)不受影响");
    }

    @Test
    @DisplayName("角色调整 Web 入口：旧访问令牌立即按旧状态失效；重新登录按新角色 403；未知用户 404")
    void roleChangeOverHttp() throws Exception {
        String admin = adminToken();
        setRoles("alice", Set.of(Permissions.ROLE_USER));
        JsonNode alice = login("alice", "alice123");
        String oldAccess = alice.get("accessToken").asText();
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isOk());

        // 调整为无角色
        MvcResult changed = mvc.perform(post("/api/admin/users/alice/roles")
                        .header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("roles_updated"))
                .andExpect(jsonPath("$.roles").isArray())
                .andReturn();
        assertEquals("[]", mapper.readTree(changed.getResponse().getContentAsString())
                .get("roles").toString());
        AuthTestLogger.result(log, "角色调整 200，旧访问令牌下次请求即失效");

        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + oldAccess))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("session_state_changed"));

        // 重新登录后按最新角色判定：已认证但无 profile:read -> 403
        JsonNode relogin = login("alice", "alice123");
        mvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + relogin.get("accessToken").asText()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"));
        AuthTestLogger.result(log, "旧令牌 401(state_changed) 与新令牌 403(denied) 不混为一类");

        // 恢复 alice 角色，避免污染共享上下文
        setRoles("alice", Set.of(Permissions.ROLE_USER));

        // 未知用户：稳定 404 user_not_found
        MvcResult notFound = mvc.perform(post("/api/admin/users/ghost/roles")
                        .header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[]}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("user_not_found"))
                .andReturn();
        assertOnlyErrorFields(notFound);
        AuthTestLogger.result(log, "未知用户 404 user_not_found，响应无内部细节");
    }

    @Test
    @DisplayName("线上链路：内容篡改的令牌 -> 401 tampered_token；伪造签名 -> 401 invalid_signature")
    void tamperedAndForgedTokenOverHttp() throws Exception {
        JsonNode alice = login("alice", "alice123");
        String access = alice.get("accessToken").asText();

        String tampered = tamperPayload(access, json -> json.replaceFirst("\"username\":\"alice\"",
                "\"username\": \"carol\""));
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("tampered_token"));

        String forged = access.substring(0, access.lastIndexOf('.') + 1)
                + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
        mvc.perform(get("/api/user/profile").header("Authorization", "Bearer " + forged))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_signature"));
        AuthTestLogger.result(log, "篡改 -> tampered_token，伪造签名 -> invalid_signature，互不相同");
    }

    // ---------- helpers ----------

    private String adminToken() throws Exception {
        return login("admin", "admin123").get("accessToken").asText();
    }

    private void setRoles(String username, java.util.Set<String> roles) throws Exception {
        String rolesJson = mapper.writeValueAsString(java.util.Map.of("roles", roles));
        mvc.perform(post("/api/admin/users/" + username + "/roles")
                        .header("Authorization", "Bearer " + adminToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(rolesJson))
                .andExpect(status().isOk());
    }

    private JsonNode listSessions(String adminToken, String username) throws Exception {
        MvcResult res = mvc.perform(get("/api/admin/users/" + username + "/sessions")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn();
        return mapper.readTree(res.getResponse().getContentAsString());
    }

    private static Set<String> sessionIds(JsonNode overview) {
        Set<String> ids = new HashSet<>();
        for (JsonNode item : overview.get("sessions")) {
            ids.add(item.get("sessionId").asText());
        }
        return ids;
    }

    /** 用访问令牌调 profile 接口，从响应体读取其所属会话标识。 */
    private String profileSessionId(String accessToken) throws Exception {
        MvcResult res = mvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andReturn();
        return mapper.readTree(res.getResponse().getContentAsString()).get("sessionId").asText();
    }

    private JsonNode login(String username, String password) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return mapper.readTree(res.getResponse().getContentAsString());
    }

    private static String tamperPayload(String compact, java.util.function.UnaryOperator<String> transform) {
        int dot = compact.indexOf('.');
        String payload = compact.substring(0, dot);
        String signaturePart = compact.substring(dot + 1);
        String json = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        String changed = transform.apply(json);
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(changed.getBytes(StandardCharsets.UTF_8));
        return encoded + "." + signaturePart;
    }

    private void assertOnlyErrorFields(MvcResult res) throws Exception {
        JsonNode body = mapper.readTree(res.getResponse().getContentAsString());
        assertEquals(2, body.size());
        assertTrue(body.has("error") && body.has("message"));
    }
}
