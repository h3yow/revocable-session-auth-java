# 可撤销会话与访问控制（本地演示）

基于 Spring Boot 3.4 / Java 21 的本地 Web 应用，演示**可撤销会话 + 令牌轮换 + 基于角色/权限的访问控制**，
在并发与异常场景下保证判定一致、失败原因可区分、内部细节不外泄。

## 1. 令牌模型

- **访问令牌（ACCESS）**：短期（默认 300s），格式 `base64url(claims JSON).base64url(HMAC-SHA256)`。
  声明含 `tokenId / sessionId / username / type / version / issuedAt / expiresAt`。
  **令牌本身不携带权限结论**；每次请求实时回查服务端会话，因此撤销/权限变更立即生效，无缓存放行窗口。
- **刷新令牌（REFRESH）**：长期（默认 3600s），同格式，`type=REFRESH`，`tokenId` 在服务端登记。
- **轮换**：每次 `POST /api/auth/refresh` 签发全新 jti 的令牌对，旧刷新令牌通过
  `AtomicBoolean.compareAndSet(false, true)` 抢占后立即失效：
  - 并发提交同一刷新令牌 → **恰好一个成功**，其余得到 `refresh_token_reused`；
  - 重放已轮换的旧令牌 → `refresh_token_reused`。
- **撤销**：`POST /api/auth/logout` 撤销会话（`revoked=true`），该会话已签发的访问令牌
  在下一次请求即被 `session_revoked` 拒绝；刷新同样被拒。
- **权限变更**：角色变更提升会话 `version`，旧访问令牌因版本不符得到
  `session_state_changed`；重新刷新/登录后按最新角色判定。

## 2. 权限模型

| 角色 | 权限 |
| --- | --- |
| `ROLE_ADMIN` | `*`（通配，命中一切） |
| `ROLE_USER` | `profile:read` |

接口要求用 `@RequirePermission("...")` 标注，任一权限命中即放行。
未认证（401）与越权（403）是不同结论。

| 端点 | 说明 |
| --- | --- |
| `POST /api/auth/login` | 登录（演示账户：`alice/alice123` → USER，`admin/admin123` → ADMIN） |
| `POST /api/auth/refresh` | 刷新并轮换令牌 |
| `POST /api/auth/logout` | 注销（撤销会话） |
| `GET /api/public/ping` | 公开 |
| `GET /api/user/profile` | 需 `profile:read` |
| `GET /api/admin/stats` | 需 `admin:stats` |

## 3. 失败分类

对外响应体固定为 `{"error": "<code>", "message": "<固定描述>"}`，
底层异常细节（堆栈、算法信息、内部标识）只写服务端日志，不返回调用方。

| error code | HTTP | 触发场景 |
| --- | --- | --- |
| `missing_token` | 401 | 无 Authorization 头 / Bearer 后为空 |
| `malformed_token` | 401 | 非 Bearer 方案、结构非两段、base64url 不可解码、claims 非法 |
| `invalid_signature` | 401 | 签名不匹配、payload 被篡改、跨密钥伪造 |
| `wrong_token_type` | 401 | 访问令牌当刷新令牌用（或反之） |
| `expired_token` | 401 | 超过 TTL |
| `session_revoked` | 401 | 会话已注销/撤销 |
| `session_state_changed` | 401 | 权限变更后旧访问令牌版本失效 |
| `refresh_token_reused` | 401 | 刷新令牌被重复使用（含并发竞争失败方） |
| `unknown_token` | 401 | 服务端无此令牌/会话登记 |
| `bad_credentials` | 401 | 用户名或密码错误（不区分用户是否存在） |
| `access_denied` | 403 | 已认证但权限不足 |

## 4. 本地验证

```bash
# 运行全部测试（23 个：令牌分类 / 轮换 / 并发刷新 / 撤销 / 越权 / HTTP 集成）
mvn test

# 启动应用（默认 8080）
mvn spring-boot:run

# 手动验证示例
curl -s -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'
# -> {"accessToken":"...","refreshToken":"...","tokenType":"Bearer","accessTokenExpiresInSeconds":300}

curl -s localhost:8080/api/user/profile -H "Authorization: Bearer <accessToken>"   # 200
curl -s localhost:8080/api/admin/stats  -H "Authorization: Bearer <accessToken>"   # 403 access_denied
curl -s localhost:8080/api/user/profile                                            # 401 missing_token

# 轮换 + 旧令牌重用
curl -s -X POST localhost:8080/api/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'          # 200，返回新令牌对
# 再次提交同一 refreshToken -> 401 refresh_token_reused

# 注销后旧访问令牌立即失效
curl -s -X POST localhost:8080/api/auth/logout -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'
curl -s localhost:8080/api/user/profile -H "Authorization: Bearer <accessToken>"   # 401 session_revoked
```

测试日志中每个用例打印 `[用例输入] / [判定依据] / [用例结果]`，服务侧打印
`刷新判定 / 刷新结果 / 访问判定结果` 等，便于核对并发与撤销场景的判定链。

## 5. 配置

`src/main/resources/application.properties`：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `app.auth.hmac-secret` | 本地演示值 | HMAC 密钥，生产环境必须更换 |
| `app.auth.access-token-ttl-seconds` | 300 | 访问令牌 TTL |
| `app.auth.refresh-token-ttl-seconds` | 3600 | 刷新令牌 TTL |

> 说明：内存存储与明文演示密码仅用于本地演示；生产环境应替换为持久化存储、
> 加盐哈希口令与密钥管理服务。
