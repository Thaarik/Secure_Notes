package com.secure.notes.security;


import com.secure.notes.model.AppRole;
import com.secure.notes.model.Role;
import com.secure.notes.model.User;
import com.secure.notes.repository.RoleRepository;
import com.secure.notes.repository.UserRepository;
import com.secure.notes.security.jwt.AuthEntryPointJwt;
import com.secure.notes.security.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

//import javax.sql.DataSource;
import java.time.LocalDate;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true )
public class WebSecurityConfig {
//      Not required in our project. just for learning purpose
//    @Autowired
//    CustomLoggingFilter customLoggingFilter;
//
//    @Autowired
//    RequestValidationFilter requestValidationFilter;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean // to be added as a filter before UsernamePasswordAuthenticationFilter and that requires a bean object
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }


    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        // some issue with this
//        http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // configure csrf protection to store the csrftoken in cookie format with HttpOnly false so that it accepts csrf tokens
//                .ignoringRequestMatchers("/api/auth/public/**")); // ignores csrf check for this url only
        //use this
        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests((requests)->
                requests // URL based security
                        .requestMatchers("/api/admin/**").hasRole("ADMIN") //"ROLE_"is removed here because hasRole method automatically appends "ROLE_" with the given role
//                        .requestMatchers("/public/**").permitAll()
//                        .requestMatchers("/admin").denyAll()
//                        .requestMatchers("/admin/**").denyAll()
                        .requestMatchers("/api/csrf-token").permitAll() // get csrf token without any authentication
                        .requestMatchers("/api/auth/public/**").permitAll() // for signin by any one
                        .anyRequest().authenticated());

        //http.formLogin(withDefaults());
//        http.csrf(AbstractHttpConfigurer::disable); // disable csrf token
//      Not required in our project. just for learning purpose
//        http.addFilterBefore(customLoggingFilter, UsernamePasswordAuthenticationFilter.class); // custom filter applies before username password authentication function
//        http.addFilterAfter(requestValidationFilter, UsernamePasswordAuthenticationFilter.class); //custom filter for request validation after username password authentication function
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler)); // default exception handling mechanism is done by unauthorizedHandler from AuthEntryPointJwt (check top)
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class); //authenticationJwtTokenFilter() to be added as a filter before UsernamePasswordAuthenticationFilter and that requires a bean object (check top)

        http.sessionManagement(session->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.httpBasic(Customizer.withDefaults()); //basic authentication (not default in-built form based auth)
        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // to encode password
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository,
                                      UserRepository userRepository,
                                      PasswordEncoder passwordEncoder // springboot injects this from the above created bean passwordEncoder
    ) {
        return args -> {
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER))); // if role exists, use that role, if not, create a new role

            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN))); // if role exists, use that role, if not, create a new role

            if (!userRepository.existsByUserName("user1")) {
                User user1 = new User("user1",
                        "user1@example.com",
                        passwordEncoder.encode("password1")); //encoding password
                user1.setAccountNonLocked(false);
                user1.setAccountNonExpired(true);
                user1.setCredentialsNonExpired(true);
                user1.setEnabled(true);
                user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                user1.setAccountExpiryDate(LocalDate.now().plusYears(1));
                user1.setTwoFactorEnabled(false);
                user1.setSignUpMethod("email");
                user1.setRole(userRole);
                userRepository.save(user1);
            }

            if (!userRepository.existsByUserName("admin")) {
                User admin = new User("admin",
                        "admin@example.com",
                        passwordEncoder.encode("adminPass")); //encoding password
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
        };
    }
    // configuring multiple users in JDBC
    // test by POST and GET request the notes using the below username and password
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource); //setting up jdbc authentication
//        // default expirations are provided in JdbcUserDetailsManager
//        if(!manager.userExists("user1")){ // creates user1 if not exists
//            manager.createUser(
//                    User.withUsername("user1")
//                            .password("{noop}password1") //{noop} letting spring security know that this password is stored in plain text without any encoding.
//                            .roles("USER")
//                            .build()
//            );
//        }
//        if(!manager.userExists("admin")){ // creates admin if not exists
//            manager.createUser(
//                    User.withUsername("admin")
//                            .password("{noop}adminPass")
//                            .roles("ADMIN")
//                            .build()
//            );
//        }
//        return manager;
//    }
}
