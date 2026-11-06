package by.darkimpulsepoint.lab4.web;

import by.darkimpulsepoint.lab4.api.ApiException;
import by.darkimpulsepoint.lab4.auth.AuthDtos.MessageResponse;
import by.darkimpulsepoint.lab4.auth.AuthDtos.UserView;
import by.darkimpulsepoint.lab4.auth.AuthService;
import by.darkimpulsepoint.lab4.security.AccessTokenClaims;
import by.darkimpulsepoint.lab4.security.AccessTokenFilter;
import by.darkimpulsepoint.lab4.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {

    private final AuthService authService;

    @GetMapping("/")
    public MessageResponse index() {
        return new MessageResponse("Test v500 lab 4!");
    }

    @GetMapping(value = "/test", produces = MediaType.TEXT_PLAIN_VALUE)
    public String test() {
        return "test failed";
    }

    @GetMapping("/api/test/all")
    public MessageResponse all() {
        return new MessageResponse("Public content.");
    }

    @GetMapping("/api/test/user")
    public MessageResponse user(@RequestAttribute(AccessTokenFilter.CLAIMS_ATTRIBUTE) AccessTokenClaims claims) {
        return new MessageResponse("User content for " + claims.username() + ".");
    }

    @GetMapping("/api/test/admin")
    public MessageResponse admin(@RequestAttribute(AccessTokenFilter.CLAIMS_ATTRIBUTE) AccessTokenClaims claims) {
        if (!claims.hasRole(User.ROLE_ADMIN)) {
            throw new ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN", "Admin role required");
        }
        return new MessageResponse("Admin content.");
    }

    @GetMapping("/api/users/me")
    public UserView me(@RequestAttribute(AccessTokenFilter.CLAIMS_ATTRIBUTE) AccessTokenClaims claims) {
        return authService.me(claims.userId());
    }
}
