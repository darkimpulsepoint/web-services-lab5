package by.darkimpulsepoint.lab4.user;

import by.darkimpulsepoint.lab4.config.AdminProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminInitializer implements ApplicationRunner {

    private final AdminProperties admin;
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        if (admin.username() == null || admin.username().isBlank() || admin.password() == null || admin.password().isBlank()
                || users.existsByUsername(admin.username())) {
            return;
        }
        User user = new User();
        user.setUsername(admin.username());
        user.setPasswordHash(passwordEncoder.encode(admin.password()));
        user.setRoles(Set.of(User.ROLE_USER, User.ROLE_ADMIN));
        user.setCreatedAt(Instant.now());
        users.save(user);
        log.info("Admin user '{}' created", admin.username());
    }
}
