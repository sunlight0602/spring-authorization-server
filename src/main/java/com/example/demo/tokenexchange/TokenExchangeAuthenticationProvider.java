package com.example.demo.tokenexchange;

import com.example.demo.repository.JpaRegisteredClientRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Duration;
import java.time.Instant;

public class TokenExchangeAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final JWKSource<SecurityContext> jwkSource;
    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;

    public TokenExchangeAuthenticationProvider(
        JWKSource<SecurityContext> jwkSource,
        OAuth2TokenGenerator<?> tokenGenerator,
        JpaRegisteredClientRepository jpaRegisteredClientRepository) {
        this.jwkSource = jwkSource;
        this.tokenGenerator = tokenGenerator;
        this.jpaRegisteredClientRepository = jpaRegisteredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        TokenExchangeAuthenticationToken tokenExchange = (TokenExchangeAuthenticationToken) authentication;

        // 驗證 ID Token
        String idToken = tokenExchange.getSubjectToken();
        RegisteredClient client = jpaRegisteredClientRepository.findByClientId("sample_client_id");

        // 建立 AccessToken
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal((Authentication) tokenExchange.getPrincipal())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizedScopes(client.getScopes())
                // .authorization(new OAuth2Authorization.Builder(tokenExchange.getRegisteredClient()).build())
                .build();

        Jwt jwt_token = (Jwt) tokenGenerator.generate(tokenContext);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwt_token.getTokenValue(),
                Instant.now(),
                Instant.now().plus(Duration.ofHours(1))
        );

        return new OAuth2AccessTokenAuthenticationToken(
            client,
            (Authentication) tokenExchange.getPrincipal(),
            accessToken
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return TokenExchangeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

