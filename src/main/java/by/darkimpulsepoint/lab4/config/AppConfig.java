package by.darkimpulsepoint.lab4.config;

import by.darkimpulsepoint.lab4.security.AccessTokenFilter;
import by.darkimpulsepoint.lab4.security.JwtService;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;

@Configuration
public class AppConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public JwtService jwtService(JwtProperties properties, Clock clock) {
        return new JwtService(properties, clock);
    }

    @Bean
    public FilterRegistrationBean<AccessTokenFilter> accessTokenFilter(JwtService jwtService) {
        FilterRegistrationBean<AccessTokenFilter> registration = new FilterRegistrationBean<>(new AccessTokenFilter(jwtService));
        registration.addUrlPatterns("/api/test/user", "/api/test/admin", "/api/auth/logout", "/api/users/me");
        return registration;
    }
}
