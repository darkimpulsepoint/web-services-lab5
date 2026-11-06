package by.darkimpulsepoint.lab4.security;

import java.time.Instant;
import java.util.List;

public record AccessTokenClaims(long userId, String username, List<String> roles, Instant issuedAt, Instant expiresAt) {

    public boolean hasRole(String role) {
        return roles.contains(role);
    }
}
