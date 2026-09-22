package com.github.h3yow.revocablesessionauthjava.domain;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * 用户聚合（不可变）。角色变更时以整体替换方式写回存储，保证并发读到一致快照。
 */
public record User(String id, String username, String passwordHash, boolean enabled, Set<Role> roles) {

    public User {
        roles = roles == null ? Set.of() : Collections.unmodifiableSet(EnumSet.copyOf(roles));
    }
}
