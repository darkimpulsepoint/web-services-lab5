package by.darkimpulsepoint.lab4.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

public final class AuthDtos {

    private AuthDtos() {
    }

    public record SignupRequest(
            @NotBlank @Size(min = 3, max = 64) @Pattern(regexp = "[A-Za-z0-9_.-]+") String username,
            @Email String email,
            @NotBlank @Size(min = 8, max = 72) String password) {
    }

    public record SigninRequest(@NotBlank String username, @NotBlank String password) {
    }

    public record RefreshRequest(@NotBlank String refreshToken) {
    }

    public record TokenPair(String accessToken, String refreshToken, String tokenType,
                            long accessExpiresIn, long refreshExpiresIn) {
    }

    public record UserView(long id, String username, String email, List<String> roles) {
    }

    public record MessageResponse(String message) {
    }
}
