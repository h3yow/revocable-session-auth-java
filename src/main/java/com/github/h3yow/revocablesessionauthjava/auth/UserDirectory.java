package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Optional;
import java.util.Set;

/** 用户账户目录（本地演示）。 */
public interface UserDirectory {

    Optional<UserAccount> findByUsername(String username);

    /**
     * 更新账户角色，使重新登录按最新角色签发。
     *
     * @return true 表示账户存在并已更新；false 表示无此账户（幂等，不抛错）
     */
    boolean updateRoles(String username, Set<String> newRoles);
}
