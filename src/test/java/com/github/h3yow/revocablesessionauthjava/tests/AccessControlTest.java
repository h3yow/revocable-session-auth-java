package com.github.h3yow.revocablesessionauthjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端访问控制测试：
 * 未认证 vs 越权可区分；注销后旧访问令牌立即失效；角色变更立即生效。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccessControlTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlTest.class);

    @Autowired
    private MockMvc mvc;

    private final ObjectMapper mapper = new ObjectMapper();

    private String login(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = mapper.readTree(result.getResponse().getContentAsString());
        String access = body.get("accessToken").asText();
        log.info("登录 输入={} 判定依据=密码校验+会话建立 结果=获得访问令牌(前16位){}...",
                username, access.substring(0, 16));
        return access;
    }

    @Test
    void unauthenticatedVsForbiddenAreDistinguishable() throws Exception {
        // 未认证：无 Authorization 头
        MvcResult noAuth = mvc.perform(get("/api/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("MISSING_TOKEN"))
                .andReturn();
        log.info("用例=未认证访问 输入=GET /api/profile 无Authorization 判定依据=拦截器未找到Bearer票据 "
                + "结果=401 {}", noAuth.getResponse().getContentAsString());

        // 越权：alice 只有 USER 角色，访问 admin 资源
        String aliceToken = login("alice", "user123");
        MvcResult forbidden = mvc.perform(get("/api/admin")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("ACCESS_DENIED"))
                .andReturn();
        log.info("用例=越权访问 输入=alice访问/admin 判定依据=实时聚合角色缺少admin:read 结果=403 {}",
                forbidden.getResponse().getContentAsString());

        // 管理员可访问
        String adminToken = login("admin", "admin123");
        MvcResult ok = mvc.perform(get("/api/admin")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn();
        log.info("用例=管理员访问 输入=admin访问/admin 判定依据=角色聚合包含admin:read 结果=200 {}",
                ok.getResponse().getContentAsString());
    }

    @Test
    void logoutInvalidatesPreviouslyIssuedAccessToken() throws Exception {
        MvcResult loginResult = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"user123\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode tokens = mapper.readTree(loginResult.getResponse().getContentAsString());
        String access = tokens.get("accessToken").asText();
        String refresh = tokens.get("refreshToken").asText();

        // 注销前可访问
        mvc.perform(get("/api/profile").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());
        log.info("用例=注销前访问 输入=已签发访问令牌 判定依据=会话revoked=false 结果=200");

        // 注销
        mvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isOk());
        log.info("用例=注销 输入=刷新令牌 判定依据=会话标记revoked 结果=200");

        // 注销后，此前签发的访问令牌必须被拒（REVOKED_SESSION）
        MvcResult after = mvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("REVOKED_SESSION"))
                .andReturn();
        log.info("用例=注销后访问 输入=同一访问令牌 判定依据=实时读取会话撤销位=true 结果=401 {}",
                after.getResponse().getContentAsString());
    }

    @Test
    void roleChangeTakesEffectImmediatelyForIssuedTokens() throws Exception {
        String adminToken = login("admin", "admin123");
        String aliceToken = login("alice", "user123");

        // 变更前：alice 无 admin 权限
        mvc.perform(get("/api/admin").header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("ACCESS_DENIED"));
        log.info("用例=角色变更前 输入=alice访问/admin 判定依据=角色仅USER 结果=403 ACCESS_DENIED");

        // 管理员将 alice 提升为 ADMIN
        mvc.perform(put("/api/admin/users/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":\"u-alice\",\"roles\":[\"USER\",\"ADMIN\"]}"))
                .andExpect(status().isOk());
        log.info("用例=角色变更 输入=admin将alice提升为ADMIN 判定依据=原子替换用户角色快照 结果=200");

        // 变更后：alice 此前签发的访问令牌立即获得 admin 权限（无需重新登录）
        mvc.perform(get("/api/admin").header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk());
        log.info("用例=角色变更后 输入=alice用同一旧访问令牌访问/admin 判定依据=实时聚合新角色包含admin:read 结果=200");

        // 降权同样立即生效
        mvc.perform(put("/api/admin/users/roles")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":\"u-alice\",\"roles\":[\"USER\"]}"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/admin").header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("ACCESS_DENIED"));
        log.info("用例=降权后 输入=alice用同一旧访问令牌访问/admin 判定依据=实时聚合角色已不含admin:read 结果=403 ACCESS_DENIED");
    }

    @Test
    void malformedAndForgedTokensAreRejectedWithDistinctCategories() throws Exception {
        MvcResult forged = mvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer not-a-real-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("FORGED_TOKEN"))
                .andReturn();
        log.info("用例=伪造令牌 输入=非三段式字符串 判定依据=结构不合法 结果=401 {}",
                forged.getResponse().getContentAsString());

        // 篡改载荷（把合法令牌中间段换掉）
        String valid = login("alice", "user123");
        String[] parts = valid.split("\\.");
        String tampered = parts[0] + ".e30." + parts[2]; // e30 = "{}"
        MvcResult tamperedResult = mvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("PAYLOAD_TAMPERED"))
                .andReturn();
        log.info("用例=内容篡改 输入=载荷替换为空JSON 判定依据=声明缺失 结果=401 {}",
                tamperedResult.getResponse().getContentAsString());

        // 签名不匹配
        String badSig = parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        MvcResult badSigResult = mvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + badSig))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SIGNATURE_INVALID"))
                .andReturn();
        log.info("用例=签名不匹配 输入=合法载荷+伪造签名 判定依据=HMAC重算不一致 结果=401 {}",
                badSigResult.getResponse().getContentAsString());

        // 拿刷新令牌当访问令牌用
        MvcResult loginResult = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"user123\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String refresh = mapper.readTree(loginResult.getResponse().getContentAsString())
                .get("refreshToken").asText();
        MvcResult wrongType = mvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + refresh))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("UNSUPPORTED_TOKEN"))
                .andReturn();
        log.info("用例=类型用错 输入=刷新令牌当访问令牌 判定依据=typ=RT而非AT 结果=401 {}",
                wrongType.getResponse().getContentAsString());
    }

    @Test
    void errorResponsesDoNotLeakInternalDetails() throws Exception {
        MvcResult result = mvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer garbage.garbage.garbage"))
                .andExpect(status().isUnauthorized())
                .andReturn();
        String body = result.getResponse().getContentAsString();
        log.info("用例=错误响应不泄露细节 输入=垃圾令牌 判定依据=响应体仅含error与message两字段 结果={}", body);
        JsonNode json = mapper.readTree(body);
        assertTrue(json.has("error") && json.has("message"));
        assertEquals(2, json.size(), "响应体不应包含堆栈/内部细节");
    }
}
