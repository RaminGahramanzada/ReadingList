package com.company.readinglist.security;


import com.company.readinglist.repository.ReaderRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import java.util.Collections;

@EnableWebSecurity
public class SecurityConfig {
    private final ReaderRepository readerRepository;

    public SecurityConfig(ReaderRepository readerRepository) {
        this.readerRepository = readerRepository;
    }

    @Bean
    public Object filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers(HttpMethod.DELETE).hasRole("ADMIN")
                                .requestMatchers("/").hasAnyRole("READER")
                                .requestMatchers("/login/**").permitAll()
                                .requestMatchers("/**").permitAll() // Permit all other requests
                                .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ).csrf((csrf) -> csrf
                        .csrfTokenRepository(new HttpSessionCsrfTokenRepository()).disable());

        return http;
    }



    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(username ->
                readerRepository.findByUsername(username)
                        .map(reader -> {
                            return User.withUsername(reader.getUsername())
                                    .password(reader.getPassword())
                                    .authorities(Collections.emptyList())
                                    .accountExpired(!reader.isAccountNonExpired())
                                    .accountLocked(!reader.isAccountNonLocked())
                                    .credentialsExpired(!reader.isCredentialsNonExpired())
                                    .disabled(!reader.isEnabled())
                                    .build();
                        })
                        .orElseThrow(() -> new UsernameNotFoundException("User '" + username + "' not found."))
        );
    }

}