package com.example.demo.tokenexchange;

import lombok.Data;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Data
public class TokenExchangeAuthenticationToken extends AbstractAuthenticationToken {

    private final Authentication clientPrincipal;
    private final String subjectToken;
    private final String subjectTokenType;
    // private final RegisteredClient registeredClient;

    public TokenExchangeAuthenticationToken(
            Authentication clientPrincipal,
            // RegisteredClient registeredClient,
            String subjectToken,
            String subjectTokenType
    ) {
        super(null);
        this.clientPrincipal = clientPrincipal;
        this.subjectToken = subjectToken;
        this.subjectTokenType = subjectTokenType;
        // this.registeredClient = registeredClient;
        setAuthenticated(false);
    }

    @Override
    public Object getPrincipal() {
        return clientPrincipal;
    }

    @Override
    public Object getCredentials() {
        return ""; // 無密碼
    }

    // public String getSubjectToken() {
    //     return subjectToken;
    // }
    //
    // public String getSubjectTokenType() {
    //     return subjectTokenType;
    // }

    // public RegisteredClient getRegisteredClient() {
    //     return registeredClient;
    // }
}

