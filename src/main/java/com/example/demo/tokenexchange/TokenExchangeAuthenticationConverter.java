package com.example.demo.tokenexchange;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class TokenExchangeAuthenticationConverter implements AuthenticationConverter {

    private final RegisteredClientRepository registeredClientRepository;

    public TokenExchangeAuthenticationConverter(RegisteredClientRepository repo) {
        this.registeredClientRepository = repo;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!"urn:ietf:params:oauth:grant-type:token-exchange"
                .equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }

        // String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        // String clientId = "sample_client_id";
        String subjectToken = request.getParameter("subject_token");
        String subjectTokenType = request.getParameter("subject_token_type");

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        // RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        // return new TokenExchangeAuthenticationToken(
        //         clientPrincipal,
        //         registeredClient,
        //         subjectToken,
        //         subjectTokenType
        // );
        return new TokenExchangeAuthenticationToken(clientPrincipal, subjectToken, subjectTokenType);
    }
}

