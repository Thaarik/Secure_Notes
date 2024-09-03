package com.secure.notes.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component // spring managed component
public class AuthEntryPointJwt implements AuthenticationEntryPoint { // AuthenticationEntry point provides custom handling for authentication related errors

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    //
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        logger.error("Unauthorized error: {}", authException.getMessage());
        System.out.println(authException);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // set to json
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // to show that it lacks authorized credentials

        final Map<String, Object> body = new HashMap<>(); // key value pairs below
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        body.put("message", authException.getMessage());
        body.put("path", request.getServletPath());
        // processing the json
        final ObjectMapper mapper = new ObjectMapper(); // converts (or) maps objects to JSON
        mapper.writeValue(response.getOutputStream(), body); // converting the above Map(body)  to JSON format
    }

}
