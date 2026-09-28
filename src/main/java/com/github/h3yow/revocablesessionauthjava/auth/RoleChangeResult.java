package com.github.h3yow.revocablesessionauthjava.auth;

/**
 * 角色变更结果（面向管理员）。字段稳定、可序列化，不含任何内部标识。
 *
 * @param accountFound    账户目录中是否存在该用户（不存在时为幂等空操作）
 * @param sessionsUpdated 本次被更新并提升版本的会话数量（这些会话此前签发的访问令牌立即失效）
 */
public record RoleChangeResult(boolean accountFound, int sessionsUpdated) {
}
