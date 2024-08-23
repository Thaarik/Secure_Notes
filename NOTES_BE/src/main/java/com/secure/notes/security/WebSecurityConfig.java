package com.secure.notes.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

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

    // configuring multiple users in JDBC
    // test by POST and GET request the notes using the below username and password
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource); //setting up jdbc authentication
        if(!manager.userExists("user1")){ // creates user1 if not exists
            manager.createUser(
                    User.withUsername("user1")
                            .password("{noop}password1") //{noop} letting spring security know that this password is stored in plain text without any encoding.
                            .roles("USER")
                            .build()
            );
        }
        if(!manager.userExists("admin")){ // creates admin if not exists
            manager.createUser(
                    User.withUsername("admin")
                            .password("{noop}adminPass")
                            .roles("ADMIN")
                            .build()
            );
        }
        return manager;
    }
}
