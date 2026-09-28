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
- **撤销**：`POST /api/auth/logout` 或管理员强制下线把会话置为 `revoked=true`，该会话已签发的
  访问/刷新令牌在下一次请求即被 `session_revoked` 拒绝。撤销、刷新换发、访问校验共用会话对象
  监视器，强制下线与"判定+换发"互斥：撤销不会被并发刷新救活，也不会与并发访问抢先后时好时坏。
- **权限变更**：管理员通过 Web 接口调整角色，提升相关会话 `version`，旧访问令牌因版本不符得到
  `session_state_changed`；重新刷新/登录后按最新角色判定。角色更新与刷新签发同样互斥。

## 1.1 管理员会话治理

以下接口均需 `admin:sessions` 权限（`ROLE_ADMIN` 通配命中），普通用户调用得到
`403 access_denied`，未登录得到 `401`，二者明确区分。

| 端点 | 说明 |
| --- | --- |
| `GET /api/admin/users/{username}/sessions` | 查看该用户**当前仍在生效**的会话概览：条数、各会话标识 `sessionId`、创建时间 `createdAtEpochMillis`、最近活动时间 `lastActiveAtEpochMillis`（已撤销会话不出现） |
| `POST /api/admin/sessions/{sessionId}/revoke` | 强制下线指定会话。返回 `{"status":"revoked"}`；会话不存在返回 `{"status":"not_found"}`；重复下线同一条结果稳定为 `revoked` |
| `POST /api/admin/users/{username}/sessions/revoke-all` | 强制下线该用户全部会话，返回 `revokedSessionCount`，幂等 |
| `POST /api/admin/users/{username}/roles` | 调整角色，请求体 `{"roles":["ROLE_USER", ...]}`；返回 `accountFound` 与 `updatedSessionCount`；用户不存在时 `status=user_not_found`（幂等空操作） |

强制下线的语义保证：

- 被下线会话此前签发的访问令牌、刷新令牌**立即**失效（每次请求实时回查会话，无缓存放行窗口）；
- 同一用户名下**其他会话照常可用**，互不牵连；其他用户更不受影响；
- 并发刷新/并发访问期间执行强制下线，结论稳定：刷新要么被 `session_revoked` 拒绝，要么抢在撤销前
  换发成功、但其新令牌在撤销落地后立即失效，不存在"撤销完又被刷新救活"。


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
| `GET/POST /api/admin/...` | 会话治理与角色调整，需 `admin:sessions`（见 1.1 节） |

## 3. 失败分类

对外响应体固定为 `{"error": "<code>", "message": "<固定描述>"}`，
底层异常细节（堆栈、算法信息、内部标识、jti、sessionId 拼串）只写服务端日志，不返回调用方。

令牌本身相关的拒绝原因已按定位问题的需要拆成互不相同、各自稳定的四类：

| error code | HTTP | 触发场景 |
| --- | --- | --- |
| `missing_token` | 401 | 无 Authorization 头 / Bearer 后为空 |
| `malformed_token` | 401 | **令牌结构本身不合法**：非 Bearer 方案、非 `payload.signature` 两段、base64url 不可解码、签名通过但 claims JSON/必填字段非法 |
| `invalid_signature` | 401 | **签名对不上**：签名段连 HMAC-SHA256 的 32 字节输出形态都不具备（明显伪造、拼接的签名） |
| `tampered_token` | 401 | **令牌内容被改动过**：签名形态合法（32 字节）但与按当前内容重算的 HMAC 不一致——payload 在传输中被修改，或令牌由别的密钥签发（对校验端可观测结论相同） |
| `session_token_mismatch` | 401 | **令牌与当前会话/用户对不上**：服务端已无此会话或刷新令牌登记、令牌声明的会话/主体与登记不一致（拿别的会话的令牌、拼接令牌、从未登记过的 jti 都落这一类） |
| `wrong_token_type` | 401 | 访问令牌当刷新令牌用（或反之） |
| `expired_token` | 401 | 超过 TTL |
| `session_revoked` | 401 | 会话已注销/被管理员强制下线 |
| `session_state_changed` | 401 | 角色变更后旧访问令牌版本失效 |
| `refresh_token_reused` | 401 | 刷新令牌被重复使用（含并发竞争失败方） |
| `bad_credentials` | 401 | 用户名或密码错误（不区分用户是否存在） |
| `access_denied` | 403 | 已认证但权限不足 |

> 归类说明（保持稳定、便于定位）：结构问题看 `malformed_token`；签名段"长得就不对"看
> `invalid_signature`；结构和签名长度都正常但内容验不过看 `tampered_token`；
> 令牌自身没问题、是与服务端登记状态对不上看 `session_token_mismatch`。
> 此前的老场景结论保持不变：垃圾串仍是 `malformed_token`，短伪造签名仍是
> `invalid_signature`，过期/类型错误/撤销/版本变更/刷新重用/坏凭据/越权的 code 均未改动；
> 原内容篡改与跨密钥签发由 `invalid_signature` 细化为 `tampered_token`，
> 原"服务端无登记（unknown_token）"并入 `session_token_mismatch`。


## 4. 本地验证

```bash
# 运行全部测试（36 个：令牌四类归因 / 轮换 / 并发刷新 / 注销 / 强制下线 /
# 角色变更 / 越权 / 管理员治理 HTTP 集成；含 30 轮撤销-刷新竞争）
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

# ===== 管理员会话治理（先登录 admin 拿令牌） =====
ADMIN=$(curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | sed -E 's/.*"accessToken":"([^"]+)".*/\1/')

# 1) alice 登录两次（制造两条会话），各自的 profile 返回里带 sessionId
curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'
# 2) 查看 alice 当前生效会话概览：条数 / sessionId / createdAt / lastActiveAt
curl -s localhost:8080/api/admin/users/alice/sessions -H "Authorization: Bearer $ADMIN"
# 3) 强制下线其中一条（用概览里的 sessionId）
curl -s -X POST localhost:8080/api/admin/sessions/<sessionId>/revoke \
  -H "Authorization: Bearer $ADMIN"                       # {"sessionId":"...","status":"revoked"}
#    被下线会话的 access/refresh 立即 401 session_revoked；另一条照常 200
#    对不存在的会话下线 -> {"status":"not_found"}；重复下线 -> 仍稳定 revoked
# 4) 强制下线 alice 全部会话
curl -s -X POST localhost:8080/api/admin/users/alice/sessions/revoke-all \
  -H "Authorization: Bearer $ADMIN"                       # {"username":"alice","revokedSessionCount":N,"status":"revoked"}

# ===== 管理员调整角色（Web 触发，旧令牌下一次请求即按新角色判定） =====
curl -s -X POST localhost:8080/api/admin/users/alice/roles \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"roles":["ROLE_ADMIN"]}'
# -> {"username":"alice","accountFound":true,"updatedSessionCount":1,"status":"updated"}
# 旧 accessToken 再访问任意受保护接口 -> 401 session_state_changed（不是放行，也不是 403）
# 用 refreshToken 换新或重新登录后 -> 新令牌按 ROLE_ADMIN 判定，/api/admin/stats 200
# 降权改回 ["ROLE_USER"] 后，旧令牌同样立即 401，重登新令牌访问 stats 为 403 access_denied

# ===== 拆分后的失败归因快速复现（访问 /api/user/profile） =====
# 结构不合法：Authorization: Bearer a.b.c            -> 401 malformed_token
# 伪签名（短签名段）：<payload>.AAAAAAAAAAAAAAAAAAAA -> 401 invalid_signature
# 内容被改：翻转真实令牌 payload 首字符              -> 401 tampered_token
# 无登记/别的会话令牌：用本服务密钥签发指向不存在会话 -> 401 session_token_mismatch
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
