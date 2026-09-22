package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.Set;

/** 本地演示用户目录中的账户（仅本地演示使用，密码为明文仅用于演示）。 */
public record UserAccount(String username, String password, Set<String> roles) {
}
