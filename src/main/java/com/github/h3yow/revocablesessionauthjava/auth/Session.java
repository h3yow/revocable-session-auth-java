package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 服务端会话。撤销标志与版本号支持并发判定：
 * revoked=true 立即拒绝对接访问；version 用于在权限变更后让旧访问令牌失效。
 * 字段可见性与原子计数保证多线程下读到的状态一致。
 */
public final class Session {

    private final String id;
    private final String username;
    private final AtomicLong version = new AtomicLong(0);
    private volatile Set<String> roles;
    private volatile Set<String> permissions;
    private volatile boolean revoked;

    public Session(String id, String username, Set<String> roles, Set<String> permissions) {
        this.id = id;
        this.username = username;
        this.roles = Set.copyOf(roles);
        this.permissions = Set.copyOf(permissions);
    }

    public String id() {
        return id;
    }

    public String username() {
        return username;
    }

    public long version() {
        return version.get();
    }

    public Set<String> roles() {
        return roles;
    }

    public Set<String> permissions() {
        return permissions;
    }

    public boolean revoked() {
        return revoked;
    }

    /** 权限/角色变更：更新集合并提升版本，使此前签发的访问令牌按 SESSION_STATE_CHANGED 拒绝。 */
    void updateRoles(Set<String> newRoles, Set<String> newPermissions) {
        this.roles = Set.copyOf(newRoles);
        this.permissions = Set.copyOf(newPermissions);
        version.incrementAndGet();
    }

    /** 撤销会话（注销/管理员操作），立即对所有访问令牌生效。 */
    void revoke() {
        this.revoked = true;
    }
}
