package com.example.demo.tokenexchange;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class IdTokenAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String subjectToken = request.getParameter("subject_token");
        String subjectTokenType = request.getParameter("subject_token_type");

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        return new TokenExchangeAuthenticationToken(clientPrincipal, subjectToken, subjectTokenType);
    }
}

