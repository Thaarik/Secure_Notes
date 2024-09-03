package com.secure.notes.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration // This CORS is applied global level. If you want apply CORS in controller level, disable this class, go to the required controller and @CrossOrigin(origins = <FE URL>, maxAge=<seconds>, allowCredentials = "true")
public class WebConfig implements WebMvcConfigurer {

    @Value("${frontend.url}") // from application.properties
    private String frontendUrl;

    //Setting CORS
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                //Applying CORS settings to specific paths
                //registery.addMapping("/api/notes/**") ....remaining code
                //Applying CORS settings for all paths
                registry.addMapping("/**")
                        .allowedOrigins(frontendUrl)
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true)
                        .maxAge(3600); //Configure how long in seconds the response from a pre-flight request can be cached by clients.

                // This is optional. Additional paths can be configured similarly
                registry.addMapping("/**")
                        .allowedOrigins(frontendUrl)
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true)
                        .maxAge(3600); //Configure how long in seconds the response from a pre-flight request can be cached by clients.
            }
        };
    }
}
