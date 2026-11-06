package by.darkimpulsepoint.lab4.web;

import by.darkimpulsepoint.lab4.auth.AuthDtos.MessageResponse;
import by.darkimpulsepoint.lab4.auth.AuthDtos.RefreshRequest;
import by.darkimpulsepoint.lab4.auth.AuthDtos.SigninRequest;
import by.darkimpulsepoint.lab4.auth.AuthDtos.SignupRequest;
import by.darkimpulsepoint.lab4.auth.AuthDtos.TokenPair;
import by.darkimpulsepoint.lab4.auth.AuthDtos.UserView;
import by.darkimpulsepoint.lab4.auth.AuthService;
import by.darkimpulsepoint.lab4.security.AccessTokenClaims;
import by.darkimpulsepoint.lab4.security.AccessTokenFilter;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    @ResponseStatus(HttpStatus.CREATED)
    public UserView signup(@Valid @RequestBody SignupRequest request) {
        return authService.signup(request);
    }

    @PostMapping("/signin")
    public TokenPair signin(@Valid @RequestBody SigninRequest request) {
        return authService.signin(request);
    }

    @PostMapping("/refresh")
    public TokenPair refresh(@Valid @RequestBody RefreshRequest request) {
        return authService.refresh(request.refreshToken());
    }

    @PostMapping("/logout")
    public MessageResponse logout(@RequestAttribute(AccessTokenFilter.CLAIMS_ATTRIBUTE) AccessTokenClaims claims) {
        authService.logout(claims.userId());
        return new MessageResponse("Logged out");
    }
}
