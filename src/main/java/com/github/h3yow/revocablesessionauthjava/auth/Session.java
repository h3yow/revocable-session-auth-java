package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 服务端会话。撤销标志与版本号支持并发判定：
 * revoked=true 立即拒绝对接访问；version 用于在权限变更后让旧访问令牌失效。
 * 字段可见性与原子计数保证多线程下读到的状态一致。
 * <p>
 * {@code lock()} 返回会话级互斥锁：刷新签发新令牌对与管理员强制下线在同一把锁上串行，
 * 保证“先撤销后刷新”不可能把已撤销会话救活，也保证撤销对已发出令牌立即生效。
 */
public final class Session {

    private final String id;
    private final String username;
    private final long createdAtEpochMillis;
    private final AtomicLong version = new AtomicLong(0);
    private volatile Set<String> roles;
    private volatile Set<String> permissions;
    private volatile boolean revoked;
    private volatile long lastActivityAtEpochMillis;

    public Session(String id, String username, Set<String> roles, Set<String> permissions,
                   long createdAtEpochMillis) {
        this.id = id;
        this.username = username;
        this.roles = Set.copyOf(roles);
        this.permissions = Set.copyOf(permissions);
        this.createdAtEpochMillis = createdAtEpochMillis;
        this.lastActivityAtEpochMillis = createdAtEpochMillis;
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

    public long createdAtEpochMillis() {
        return createdAtEpochMillis;
    }

    public long lastActivityAtEpochMillis() {
        return lastActivityAtEpochMillis;
    }

    /** 刷新/访问成功时记录最近活动时间。 */
    void touch(long nowEpochMillis) {
        this.lastActivityAtEpochMillis = nowEpochMillis;
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

    /**
     * 会话级互斥锁。刷新（读撤销位 + 签发新令牌对）与强制下线（置撤销位）
     * 必须在同一把锁上串行，避免撤销与轮换抢时序。
     */
    public Object lock() {
        return this;
    }
}
