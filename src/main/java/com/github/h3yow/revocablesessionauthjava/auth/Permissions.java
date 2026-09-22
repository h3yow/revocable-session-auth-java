package com.github.h3yow.revocablesessionauthjava.auth;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 角色 -> 权限的映射规则（本地演示）。
 * <ul>
 *   <li>ROLE_ADMIN 拥有通配权限 {@value #WILDCARD}，命中一切资源；</li>
 *   <li>ROLE_USER 仅拥有 profile:read。</li>
 * </ul>
 */
public final class Permissions {

    public static final String WILDCARD = "*";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_USER = "ROLE_USER";
    public static final String PROFILE_READ = "profile:read";
    public static final String ADMIN_STATS = "admin:stats";

    private Permissions() {
    }

    public static Set<String> forRoles(Set<String> roles) {
        Set<String> permissions = new LinkedHashSet<>();
        if (roles == null) {
            return permissions;
        }
        if (roles.contains(ROLE_ADMIN)) {
            permissions.add(WILDCARD);
            return permissions;
        }
        if (roles.contains(ROLE_USER)) {
            permissions.add(PROFILE_READ);
        }
        return permissions;
    }

    /** 判定已授权集合是否满足资源要求（ADMIN 通配或任一命中）。 */
    public static boolean satisfies(Set<String> granted, String[] required) {
        if (granted == null || required == null || required.length == 0) {
            return true;
        }
        if (granted.contains(WILDCARD)) {
            return true;
        }
        for (String p : required) {
            if (granted.contains(p)) {
                return true;
            }
        }
        return false;
    }
}
