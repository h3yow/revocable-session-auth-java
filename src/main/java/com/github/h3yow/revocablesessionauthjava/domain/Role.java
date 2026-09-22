package com.github.h3yow.revocablesessionauthjava.domain;

import java.util.Collections;
import java.util.Set;

/**
 * 角色及其直接拥有的权限。权限判定始终实时聚合用户当前角色，
 * 不依赖访问令牌中携带的任何快照声明。
 */
public enum Role {

    USER(Set.of("profile:read")),
    ADMIN(Set.of("profile:read", "admin:read", "admin:manage"));

    private final Set<String> permissions;

    Role(Set<String> permissions) {
        this.permissions = permissions;
    }

    public Set<String> permissions() {
        return Collections.unmodifiableSet(permissions);
    }
}
