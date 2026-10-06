package com.jwttokenservice.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationEntryPoint point;

    @Autowired
    private JwtAuthenticationFilter filter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // Disable CSRF because this is a stateless REST API
                .csrf(csrf -> csrf.disable())

                // Authorization rules

                .authorizeHttpRequests(auth -> auth
                        // Swagger
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**"
                        ).permitAll()

                        .requestMatchers("/auth/login").permitAll()
                        .requestMatchers("/test").authenticated()
                        .anyRequest().authenticated()
                )

                // Handle authentication failures
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(point)
                )

                // JWT authentication = stateless
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        // Run JWT filter before Spring Security's username/password filter
        http.addFilterBefore(
                filter,
                UsernamePasswordAuthenticationFilter.class
        );

        return http.build();
    }
}