package com.secure.notes.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests)->
                requests
//                        .requestMatchers("/contact").permitAll()
//                        .requestMatchers("/public/**").permitAll()
//                        .requestMatchers("/admin").denyAll()
//                        .requestMatchers("/admin/**").denyAll()
                        .anyRequest().authenticated());
        //http.formLogin(withDefaults());
        http.csrf(AbstractHttpConfigurer::disable); // disable csrf token
        http.sessionManagement(session->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.httpBasic(Customizer.withDefaults()); //basic authentication (not default in-built form based auth)
        return http.build();
    }
}
