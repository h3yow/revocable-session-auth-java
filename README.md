# 可撤销会话与访问控制（本地演示）

一个本地运行的 Spring Boot 应用，演示**可撤销会话**、**刷新令牌轮换**与**实时权限判定**，
保证在并发与异常场景下，登录态、权限判定与失败原因保持一致、可解释。

## 1. 令牌模型

| 令牌 | 类型声明 | 有效期 | 用途 |
|------|----------|--------|------|
| 访问令牌（AT） | `typ=AT` | 5 分钟（短期） | 访问受保护资源 |
| 刷新令牌（RT） | `typ=RT` | 14 天（长期） | 换取新令牌对 |

- 线路格式：`base64url(header).base64url(payload).base64url(HMAC-SHA256(header.payload))`，
  头部固定 `{"alg":"HS256"}`，载荷含 `typ/sub/sid/jti/iat/exp`。
- **刷新即轮换**：每次刷新签发全新的令牌对，旧刷新令牌立即失效。
- **重放保护**：旧刷新令牌或未知 jti 的令牌再次出现，视为可能已泄露，
  整个会话族被连带撤销（OAuth 2.0 BCP 推荐的检测式撤销语义）。
- **并发安全**：轮换通过 `ConcurrentHashMap.compute` 原子读改写完成，
  同一刷新令牌在并发请求下**恰好成功一次**，其余请求得到 `REUSE_DETECTED`。

## 2. 权限模型

- 角色 → 权限映射（`Role` 枚举）：
  - `USER` → `profile:read`
  - `ADMIN` → `profile:read`、`admin:read`、`admin:manage`
- 访问令牌**不携带**任何角色/权限快照；每次请求都由拦截器实时聚合用户当前角色判定。
- 因此**注销**或**角色变更**后，此前已签发的访问令牌按最新状态处理，立即生效，
  不存在缓存或时序放行窗口。
- 演示用户：`alice/user123`（USER）、`admin/admin123`（USER+ADMIN）。

## 3. 失败分类（可区分、不泄露底层细节）

所有失败统一映射为 `TokenError`，响应体仅含 `{error, message}` 两个字段：

| 错误码 | HTTP | 触发场景 |
|--------|------|----------|
| `MISSING_TOKEN` | 401 | 无 Authorization 头 / 非 Bearer 方案 / 空白票据 |
| `FORGED_TOKEN` | 401 | 非三段式结构、Base64 非法、头部 alg 不受支持 |
| `PAYLOAD_TAMPERED` | 401 | 载荷无法解析或缺少必要声明（内容被篡改） |
| `SIGNATURE_INVALID` | 401 | 结构合法但 HMAC 校验失败（签名不匹配） |
| `UNSUPPORTED_TOKEN` | 401 | 令牌类型用错（如拿 RT 当 AT 用） |
| `EXPIRED_TOKEN` | 401 | 令牌已过期 |
| `REPLAYED_REFRESH_TOKEN` | 401 | 刷新令牌已轮换（旧令牌） |
| `REUSE_DETECTED` | 401 | 检测到刷新令牌重复使用，会话族已撤销 |
| `REVOKED_SESSION` | 401 | 会话已注销/撤销 |
| `UNKNOWN_SESSION` | 401 | 会话不存在 |
| `USER_UNAVAILABLE` | 401 | 用户不存在或已停用 |
| `BAD_CREDENTIALS` | 401 | 用户名或密码错误（不区分两者，防账号枚举） |
| `ACCESS_DENIED` | 403 | 已认证但权限不足 |

底层异常（解析错误、加密异常等）只记录在服务端日志，绝不回传调用方。

## 4. API 一览

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| POST | `/api/auth/login` | 公开 | 登录，返回令牌对 |
| POST | `/api/auth/refresh` | 公开 | 刷新（轮换）令牌对 |
| POST | `/api/auth/logout` | 公开 | 注销，撤销会话 |
| GET | `/api/profile` | `profile:read` | 当前用户信息 |
| GET | `/api/admin` | `admin:read` | 管理视图 |
| PUT | `/api/admin/users/roles` | `admin:manage` | 变更用户角色（立即生效） |

## 5. 本地验证

```bash
# 运行全部测试（令牌轮换、并发刷新、撤销后访问、越权访问）
mvn test

# 启动应用
mvn spring-boot:run

# 手工验证示例
curl -s -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"user123"}'

curl -s localhost:8080/api/profile -H "Authorization: Bearer <accessToken>"
curl -s localhost:8080/api/admin   -H "Authorization: Bearer <accessToken>"   # 403 ACCESS_DENIED
```

测试日志中每条用例均打印 **输入 / 判定依据 / 结果**，例如：

```
用例=16线程并发刷新同一令牌 输入=共享同一刷新令牌x16 判定依据=ConcurrentHashMap.compute原子读改写 结果=成功1次, REUSE_DETECTED拒绝15次, 其它失败0次
```

## 6. 关键设计决策

1. **会话撤销位实时生效**：访问令牌虽为不记名票据，但每次请求都实时查询会话的
   `revoked` 标志，注销后立即拒绝。
2. **权限实时聚合**：不缓存角色，角色变更对已签发令牌立即生效。
3. **原子轮换**：`SessionStore.rotate` 在 Map bin 锁内完成“比对-写回”，
   并发下串行判定，杜绝双重换发。
4. **重放即撤销族**：旧刷新令牌重放视为泄露信号，撤销整个会话族，
   合法用户需重新登录，攻击者无法继续使用任何已签发令牌。
