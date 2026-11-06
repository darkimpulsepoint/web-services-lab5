package by.darkimpulsepoint.lab4.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class AccessTokenFilter extends OncePerRequestFilter {

    public static final String CLAIMS_ATTRIBUTE = "lab4.accessTokenClaims";
    private static final String BEARER = "Bearer ";

    private final JwtService jwtService;

    public AccessTokenFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            AccessTokenClaims claims = jwtService.verifyAccessToken(extractToken(request));
            request.setAttribute(CLAIMS_ATTRIBUTE, claims);
        } catch (TokenException e) {
            log.warn("Rejected access token on {} {}: {}", request.getMethod(), request.getRequestURI(), e.getCode());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
            response.getWriter().write("{\"error\":\"" + e.getCode() + "\",\"message\":\"" + e.getMessage() + "\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private static String extractToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return header.substring(BEARER.length()).trim();
        }
        return request.getHeader("x-access-token");
    }
}
