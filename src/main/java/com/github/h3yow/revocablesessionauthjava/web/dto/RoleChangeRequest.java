package com.github.h3yow.revocablesessionauthjava.web.dto;

import java.util.List;

/**
 * 管理员角色变更请求（用于演示权限实时生效）。
 */
public record RoleChangeRequest(String userId, List<String> roles) {
}
