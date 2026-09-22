package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Optional;

/** 用户账户目录（本地演示）。 */
public interface UserDirectory {

    Optional<UserAccount> findByUsername(String username);
}
