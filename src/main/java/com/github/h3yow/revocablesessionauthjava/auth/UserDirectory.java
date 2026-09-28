package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Optional;
import java.util.Set;

/** 用户账户目录（本地演示）。 */
public interface UserDirectory {

    Optional<UserAccount> findByUsername(String username);

    /**
     * 更新用户角色（管理员 Web 触发）。角色同时落盘到目录，使该用户后续重新登录即按新角色签发；
     * 已存在的会话由 AuthService 同步提升版本。用户不存在返回 false。
     */
    boolean updateRoles(String username, Set<String> newRoles);
}
