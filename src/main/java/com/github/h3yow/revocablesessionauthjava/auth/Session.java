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
    private final long createdAtEpochMillis;
    private final AtomicLong lastActiveAtEpochMillis;
    private final AtomicLong version = new AtomicLong(0);
    private volatile Set<String> roles;
    private volatile Set<String> permissions;
    private volatile boolean revoked;

    public Session(String id, String username, Set<String> roles, Set<String> permissions,
                   long createdAtEpochMillis) {
        this.id = id;
        this.username = username;
        this.roles = Set.copyOf(roles);
        this.permissions = Set.copyOf(permissions);
        this.createdAtEpochMillis = createdAtEpochMillis;
        this.lastActiveAtEpochMillis = new AtomicLong(createdAtEpochMillis);
    }

    public String id() {
        return id;
    }

    public String username() {
        return username;
    }

    public long createdAtEpochMillis() {
        return createdAtEpochMillis;
    }

    public long lastActiveAtEpochMillis() {
        return lastActiveAtEpochMillis.get();
    }

    /** 更新最近活动时间（访问校验通过 / 刷新成功时），仅向前推进。 */
    void touch(long nowEpochMillis) {
        lastActiveAtEpochMillis.updateAndGet(prev -> Math.max(prev, nowEpochMillis));
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

    /**
     * 读取会话的安全判定快照（撤销标志 + 版本）。与 {@link #revoke()}、{@link #updateRoles}、
     * 刷新换发共用同一把监视器锁：访问校验不会在"刷新刚签发、撤销尚未落定"的窗口读到旧状态，
     * 从而保证撤销与并发访问/刷新竞争时结论稳定。
     */
    synchronized long snapshotVersionIfActive() {
        if (revoked) {
            return -1L;
        }
        return version.get();
    }

    /**
     * 权限/角色变更：更新集合并提升版本，使此前签发的访问令牌按 SESSION_STATE_CHANGED 拒绝。
     * 与 {@link #revoke()}、刷新换发共用同一把监视器锁：角色变更与"判定+签发"互斥，
     * 新签发的令牌一定携带变更后的版本号，不会出现按旧角色放行的新令牌。
     */
    synchronized void updateRoles(Set<String> newRoles, Set<String> newPermissions) {
        this.roles = Set.copyOf(newRoles);
        this.permissions = Set.copyOf(newPermissions);
        version.incrementAndGet();
    }

    /**
     * 撤销会话（注销/管理员强制下线），立即对所有访问令牌生效。
     * 与刷新换发的临界区共用本对象监视器：撤销与"判定未撤销+签发新令牌"
     * 互斥，保证强制下线不会被并发刷新抢时序放行或"救活"。
     */
    synchronized void revoke() {
        this.revoked = true;
    }
}
