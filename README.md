# 可撤销会话与访问控制（本地演示）

基于 Spring Boot 3.4 / Java 21 的本地 Web 应用，演示**可撤销会话 + 令牌轮换 + 基于角色/权限的访问控制 + 管理员会话治理**，
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
- **撤销（保持不变的老行为）**：`POST /api/auth/logout` 与管理员强制下线都把会话置为 `revoked=true`，
  该会话已签发的访问令牌在下一次请求即被 `session_revoked` 拒绝；尚未消费的刷新令牌刷新时同样被拒。
- **权限变更（保持不变的老行为）**：角色变更提升会话 `version`，旧访问令牌因版本不符得到
  `session_state_changed`；重新刷新/登录后按最新角色判定。

### 撤销与并发刷新的一致性（强制下线为何不会"抢不赢"）

访问判定实时回查会话，不存在缓存放行；刷新换发与撤销共用同一个会话对象监视器：

- 刷新线程在临界区内执行"判定未撤销 → 签发新令牌对"，撤销线程执行 `revokeIfActive()`，二者互斥；
- 撤销先到：本次刷新得到 `session_revoked`，不会救活会话；
- 刷新先到：拿到的新令牌对也属于该会话，撤销随后生效，新令牌在下一次请求/刷新立即被 `session_revoked` 拒绝。

因此不存在"撤销和放行抢先后时好时坏"或"撤销完又被刷新救回来"的窗口（`SessionAdminServiceTest` 用 30 轮
闭锁竞争反复验证）。

## 2. 权限模型与接口

| 角色 | 权限 |
| --- | --- |
| `ROLE_ADMIN` | `*`（通配，命中一切，含 `admin:sessions` / `admin:roles`） |
| `ROLE_USER` | `profile:read` |

接口要求用 `@RequirePermission("...")` 标注，任一权限命中即放行。
未认证（401）与越权（403）是不同结论。

| 端点 | 权限 | 说明 |
| --- | --- | --- |
| `POST /api/auth/login` | 公开 | 登录（演示账户：`alice/alice123` → USER，`admin/admin123` → ADMIN） |
| `POST /api/auth/refresh` | 公开 | 刷新并轮换令牌 |
| `POST /api/auth/logout` | 公开（凭刷新令牌） | 注销（撤销本人会话） |
| `GET /api/public/ping` | 公开 | 公开探测 |
| `GET /api/user/profile` | `profile:read` | 用户资料 |
| `GET /api/admin/stats` | `admin:stats` | 管理员统计 |
| `GET /api/admin/users/{username}/sessions` | `admin:sessions` | **会话概览**：数量、会话标识、创建时间、最近活动时间（仅未撤销） |
| `POST /api/admin/sessions/{sessionId}/revoke` | `admin:sessions` | **强制下线单条会话**；不存在 → 404 `session_not_found`；重复下线幂等成功 |
| `POST /api/admin/users/{username}/sessions/revoke` | `admin:sessions` | **强制下线某用户全部会话**；返回本次新下线数量，重复调用为 0 |
| `POST /api/admin/users/{username}/roles` | `admin:roles` | **调整角色**；旧访问令牌下一次请求即失效；未知用户 → 404 `user_not_found` |

> 单条下线只精确作用于目标会话，同一用户的其他会话、其他用户的会话都不受牵连。
> 角色变更请求体形如 `{"roles":["ROLE_USER"]}`，传空数组 `{"roles":[]}` 表示清空全部角色。

## 3. 失败分类（拆分后）

对外响应体固定为 `{"error": "<code>", "message": "<固定描述>"}`，
底层异常细节（堆栈、算法信息、jti/会话 id 等内部标识拼串）只写服务端日志，不返回调用方。

| error code | HTTP | 触发场景 |
| --- | --- | --- |
| `missing_token` | 401 | 无 Authorization 头 / Bearer 后为空 |
| `malformed_token` | 401 | 非 Bearer 方案、结构非两段、base64url 不可解码、claims JSON 非法或缺必填字段 |
| `tampered_token` | 401 | **令牌内容被改动过**：载荷可解析，但不是签发端的规范化字节（手工改写 claims、夹带空白/重排等） |
| `invalid_signature` | 401 | **签名对不上但载荷本身完好**：伪造签名段、跨密钥签发 |
| `session_token_mismatch` | 401 | **令牌与服务端会话/主体对不上**：声明主体与会话登记主体不一致、刷新令牌登记到别的会话 |
| `unknown_token` | 401 | **服务端无登记**：无此会话、无此刷新令牌 jti |
| `wrong_token_type` | 401 | 访问令牌当刷新令牌用（或反之） |
| `expired_token` | 401 | 超过 TTL |
| `session_revoked` | 401 | 会话已注销/被管理员强制下线 |
| `session_state_changed` | 401 | 角色变更后旧访问令牌版本失效 |
| `refresh_token_reused` | 401 | 刷新令牌被重复使用（含并发竞争失败方） |
| `bad_credentials` | 401 | 用户名或密码错误（不区分用户是否存在） |
| `access_denied` | 403 | 已认证但权限不足（与 401 未认证严格区分） |
| `session_not_found` | 404 | 单条下线的目标会话不存在 |
| `user_not_found` | 404 | 角色调整的目标用户不存在 |
| `malformed_request` | 400 | 请求体 JSON 无法解析 |
| `internal_error` | 500 | 兜底，不附带任何内部细节 |

**判定口径说明**：HMAC 不匹配时，校验端把 claims 按签发端规范化重新序列化并与提交载荷逐字节比对——
不一致即"内容被改动"（`tampered_token`）；一致即"载荷没动、只是签名对不上"（`invalid_signature`）。
这是确定性、可复现的口径；单纯翻转 base64 字符导致 JSON 无法解析的，属于结构不合法（`malformed_token`）。

### 本次保持不变的老行为

- 轮换的并发单次成功、重放 → `refresh_token_reused`；
- 注销/撤销后旧访问与刷新立即 `session_revoked`；
- 角色变更后旧访问令牌 `session_state_changed`，刷新/重登按新角色；
- 公开接口放行、未认证 401、越权 403；错误凭据 401 `bad_credentials` 且不区分用户是否存在；
- 错误响应只有 `error/message` 两个字段，不外泄算法、堆栈、内部标识。

## 4. 本地验证

```bash
# 运行全部测试（37 个：令牌细分分类 / 轮换 / 并发刷新 / 撤销 /
# 管理员治理（概览、单条/全部下线、幂等、撤销vs刷新竞争）/ 角色调整 / HTTP 集成）
mvn test

# 启动应用（默认 8080）
mvn spring-boot:run
```

以下脚本可一步步复现治理场景（需要 `jq`；没有也可手工复制令牌）：

```bash
BASE=http://localhost:8080

# 1) 管理员登录；同一普通用户开两条会话（模拟两台设备）
ADMIN=$(curl -s -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}')
AT=$(echo "$ADMIN" | jq -r .accessToken)

D1=$(curl -s -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}')
D2=$(curl -s -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}')
A1=$(echo "$D1" | jq -r .accessToken); R1=$(echo "$D1" | jq -r .refreshToken)
A2=$(echo "$D2" | jq -r .accessToken)

# 2) 会话概览：数量 / 会话标识 / 创建时间 / 最近活动时间
curl -s $BASE/api/admin/users/alice/sessions -H "Authorization: Bearer $AT" | jq

# 3) 强制下线其中一条（用该令牌访问 profile 拿到它的 sessionId）
SID=$(curl -s $BASE/api/user/profile -H "Authorization: Bearer $A1" | jq -r .sessionId)
curl -s -X POST $BASE/api/admin/sessions/$SID/revoke -H "Authorization: Bearer $AT" | jq

# 被下线会话：访问与刷新立即 401 session_revoked
curl -s -o /dev/null -w '%{http_code}\n' $BASE/api/user/profile -H "Authorization: Bearer $A1"   # 401
curl -s -X POST $BASE/api/auth/refresh -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$R1\"}"                                                                 # session_revoked
# 同用户另一条照常 200
curl -s -o /dev/null -w '%{http_code}\n' $BASE/api/user/profile -H "Authorization: Bearer $A2"   # 200

# 4) 幂等与不存在目标
curl -s -X POST $BASE/api/admin/sessions/$SID/revoke -H "Authorization: Bearer $AT" | jq         # 仍 200
curl -s -X POST $BASE/api/admin/sessions/sess-ghost/revoke -H "Authorization: Bearer $AT" | jq   # 404 session_not_found

# 5) 全部下线某用户
curl -s -X POST $BASE/api/admin/users/alice/sessions/revoke -H "Authorization: Bearer $AT" | jq  # revokedSessionCount
curl -s $BASE/api/admin/users/alice/sessions -H "Authorization: Bearer $AT" | jq                 # 空列表

# 6) 角色调整：旧访问令牌立即失效，重登按新角色判定
D3=$(curl -s -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}')
A3=$(echo "$D3" | jq -r .accessToken)
curl -s -X POST $BASE/api/admin/users/alice/roles -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{"roles":[]}' | jq       # 清空角色
curl -s -o /dev/null -w '%{http_code}\n' $BASE/api/user/profile -H "Authorization: Bearer $A3"   # 401 session_state_changed
D4=$(curl -s -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}')
A4=$(echo "$D4" | jq -r .accessToken)
curl -s -o /dev/null -w '%{http_code}\n' $BASE/api/user/profile -H "Authorization: Bearer $A4"   # 403 access_denied

# 7) 拆分后的失败归因（以篡改令牌为例）
PAYLOAD=$(echo "$A4" | cut -d. -f1); SIG=$(echo "$A4" | cut -d. -f2)
TAMPERED=$(echo -n "$(echo -n "$PAYLOAD" | base64 -d 2>/dev/null | sed 's/"username":"alice"/"username": "carol"/' \
  | base64 | tr '+/' '-_' | tr -d '=\n').$SIG")
curl -s $BASE/api/user/profile -H "Authorization: Bearer $TAMPERED" | jq                          # tampered_token
```

> 上面第 7 步的 `base64/sed` 管道仅为手工演示；自动化测试（`HmacTokenServiceTest`、
> `AuthServiceTest`、`AdminApiTest`）用同一规范化口径确定性覆盖 `tampered_token` /
> `invalid_signature` / `malformed_token` / `session_token_mismatch` / `unknown_token`。

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
