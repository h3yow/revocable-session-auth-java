# 可撤销会话与访问控制（本地演示）

基于 Spring Boot 3.4 / Java 21 的本地 Web 应用，演示**可撤销会话 + 令牌轮换 + 基于角色/权限的访问控制
+ 面向管理员的会话治理（会话概览 / 强制下线 / 角色调整）**，
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
- **撤销**：`POST /api/auth/logout` 与管理员强制下线都把会话置为 `revoked=true`，
  该会话已签发的访问令牌在下一次请求即被 `session_revoked` 拒绝；刷新同样被拒。
- **撤销与刷新不抢时序**：刷新的“查撤销位 + 签发新令牌对”临界区，与强制下线的“置撤销位”
  在同一把**会话级锁**上串行。撤销要么发生在刷新之前（刷新直接被 `session_revoked` 拒绝，
  会话不可能被轮换“救活”），要么发生在刷新之后（新令牌引用的仍是已撤销会话，下一次请求立即被拒）。
- **权限变更**：角色变更提升会话 `version`，旧访问令牌因版本不符得到
  `session_state_changed`；重新刷新/登录后按最新角色判定。

## 2. 权限模型

| 角色 | 权限 |
| --- | --- |
| `ROLE_ADMIN` | `*`（通配，命中一切，含 `admin:session` 治理权限） |
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
| `GET /api/admin/users/{username}/sessions` | **管理员**：查看该用户当前生效会话概览（需 `admin:session`） |
| `POST /api/admin/sessions/{sessionId}/revoke` | **管理员**：强制下线单条会话（幂等） |
| `POST /api/admin/users/{username}/sessions/revoke` | **管理员**：强制下线该用户全部生效会话 |
| `POST /api/admin/users/{username}/roles` | **管理员**：调整用户角色，请求体 `{"roles":["ROLE_USER"]}` |

管理员会话概览返回示例（只含稳定标识与时间，不含令牌原文等内部细节）：

```json
{
  "username": "alice",
  "activeSessionCount": 2,
  "sessions": [
    {"sessionId": "sess-...", "createdAtEpochMillis": 1780000000000, "lastActivityAtEpochMillis": 1780000000000}
  ]
}
```

强制下线单条会话返回 `{sessionId, found, revoked, alreadyRevoked}`：
会话不存在 → `found=false`（稳定 200，不冒底层错误）；首次下线 → `alreadyRevoked=false`；
重复下线已撤销会话 → `found=true, alreadyRevoked=true`，结论可重复。
批量下线返回 `{username, revokedSessionCount, sessionIds}`，已撤销会话不重复计数。

## 3. 失败分类

对外响应体固定为 `{"error": "<code>", "message": "<固定描述>"}`，
底层异常细节（堆栈、算法信息、内部标识拼串）只写服务端日志，不返回调用方。

| error code | HTTP | 触发场景 |
| --- | --- | --- |
| `missing_token` | 401 | 无 Authorization 头 / Bearer 后为空 |
| `malformed_token` | 401 | 非 Bearer 方案、结构非两段、base64url 不可解码、claims 非法（**结构本身不成立**） |
| `invalid_signature` | 401 | 签名不匹配：payload 内容被改动，或跨密钥伪造签名（密码学上二者观测等价，统一归此码） |
| `wrong_token_type` | 401 | 访问令牌当刷新令牌用（或反之） |
| `expired_token` | 401 | 超过 TTL |
| `session_revoked` | 401 | 会话已注销/被管理员强制下线 |
| `session_state_changed` | 401 | 权限变更后旧访问令牌版本失效 |
| `refresh_token_reused` | 401 | 刷新令牌被重复使用（含并发竞争失败方） |
| `unknown_token` | 401 | 刷新令牌 jti 在服务端**完全没有登记**（老结论不变） |
| `session_not_found` | 401 | **新增**：令牌结构/签名合法、jti 有登记，但服务端已无对应会话登记 |
| `token_session_mismatch` | 401 | **新增**：令牌与当前会话/用户对不上（拿了别的会话的令牌：令牌声称会话与刷新登记指向不一致、或令牌主体与会话不一致） |
| `bad_credentials` | 401 | 用户名或密码错误（不区分用户是否存在） |
| `access_denied` | 403 | 已认证但权限不足（与“未登录/令牌不合法”的 401 严格区分） |
| `user_not_found` | 404 | 管理员治理的目标用户不存在 |

> **本次拆分说明（兼容范围）**：原先笼统的“令牌/会话对不上”被细分为三个互不重叠的稳定码——
> `unknown_token`（jti 无登记）、`session_not_found`（会话登记缺失）、
> `token_session_mismatch`（令牌归属与服务端状态不一致）。
> 其余既有码与触发场景全部保持不变：`malformed_token`、`invalid_signature`、
> `session_revoked`、`session_state_changed`、`refresh_token_reused`、`wrong_token_type`、
> `expired_token`、`missing_token`、`bad_credentials`、`access_denied` 的结论与 HTTP 状态码均未改动。
> “内容被改动”与“签名对不上”在 HMAC 模型下观测上完全等价（改动内容必然导致签名不匹配，
> 反之也无法可靠区分），因此二者稳定地同归 `invalid_signature`，不做人为臆测拆分。

## 4. 本地验证

```bash
# 运行全部测试（37 个：令牌分类 / 轮换 / 并发刷新 / 撤销 / 越权 /
#               管理员会话治理 / 强制下线并发 / 角色调整 / 归因拆分 / HTTP 集成）
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

### 4.1 管理员会话治理复现

先以管理员登录拿到 `ADMIN_TOKEN`，再让 alice 登录两次（模拟两台设备）：

```bash
ADMIN_TOKEN=$(curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | sed -E 's/.*"accessToken":"([^"]+)".*/\1/')

# 1) 查看 alice 当前生效会话（条数 / 标识 / 创建与最近活动时间）
curl -s localhost:8080/api/admin/users/alice/sessions -H "Authorization: Bearer $ADMIN_TOKEN"

# 2) 强制下线其中一条：该会话旧 access/refresh 立即失效（session_revoked），另一条照常
curl -s -X POST localhost:8080/api/admin/sessions/<sessionId>/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# 重复执行 -> alreadyRevoked=true；下线不存在的会话 -> found=false（均为稳定 200）

# 3) 一键强制下线 alice 全部生效会话
curl -s -X POST localhost:8080/api/admin/users/alice/sessions/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# 4) 调整角色：alice 升为管理员（旧访问令牌下一次请求 -> 401 session_state_changed；
#    刷新或重新登录后的新令牌 -> /api/admin/stats 200）
curl -s -X POST localhost:8080/api/admin/users/alice/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"roles":["ROLE_ADMIN"]}'
```

并发撤销场景由单测 `AdminGovernanceServiceTest.revokeRacingWithRefreshCannotReviveSession`
以 30 轮“刷新线程 + 撤销线程”同时放行的方式确定性复现：每轮结束后旧令牌与可能轮换出的
新令牌都必须不可用，验证撤销绝不会被并发刷新救活。

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
