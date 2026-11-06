package by.darkimpulsepoint.lab4.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByRefreshTokenHash(String refreshTokenHash);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    /**
     * Атомарная ротация: заменяет хеш, только если предъявлен именно текущий и ещё действующий токен.
     * Два параллельных запроса с одним refresh-токеном не получат две пары — второй обновит 0 строк.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update User u set u.refreshTokenHash = :newHash, u.refreshTokenExpiresAt = :newExpiresAt
            where u.id = :id and u.refreshTokenHash = :oldHash and u.refreshTokenExpiresAt > :now
            """)
    int rotateRefreshToken(@Param("id") long id, @Param("oldHash") String oldHash, @Param("newHash") String newHash,
                           @Param("newExpiresAt") Instant newExpiresAt, @Param("now") Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update User u set u.refreshTokenHash = null, u.refreshTokenExpiresAt = null where u.id = :id")
    int clearRefreshToken(@Param("id") long id);
}
