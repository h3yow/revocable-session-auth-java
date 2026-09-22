package com.github.h3yow.revocablesessionauthjava.web.dto;

import java.util.List;

public record UserView(String userId, String username, List<String> roles, boolean enabled) {
}
