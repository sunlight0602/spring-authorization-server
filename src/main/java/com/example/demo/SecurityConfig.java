package com.example.demo;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.example.demo.repository.ClientRepository;
import com.example.demo.repository.JpaRegisteredClientRepository;
import com.example.demo.tokenexchange.IdTokenAuthenticationConverter;
import com.example.demo.tokenexchange.TokenExchangeAuthenticationConverter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            JpaRegisteredClientRepository registeredClientRepository,
            OAuth2TokenGenerator<?> tokenGenerator,
            JWKSource<SecurityContext> jwkSource
    ) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/oauth2/token").permitAll()
                .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()));

        authorizationServerConfigurer
            .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                .accessTokenRequestConverter(authenticationConverter())
                .authenticationProvider(new ServiceAccountAuthenticationProvider(...))
                .authenticationProvider(new IdTokenAuthenticationProvider(...))
            );
        http.apply(authorizationServerConfigurer);
        return http.build();
    }

    @Bean
    public JpaRegisteredClientRepository registeredClientRepository(ClientRepository clientRepository) {
        return new JpaRegisteredClientRepository(clientRepository);
        // 這代表你用官方提供的 JpaRegisteredClientRepository 作為 SAS 所需的 RegisteredClientRepository 實作，
        // 但資料存取邏輯交給你自己寫的 JPA 介面來做。
        // 我找不到那個 dependency?
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // The JWK Set endpoint is configured only if a JWKSource<SecurityContext> @Bean is registered.
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder) {
        // 建立各種 Token 生成器
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        // 包裝成 DelegatingTokenGenerator，依序嘗試這些生成器
        return new DelegatingOAuth2TokenGenerator(
            jwtGenerator,
            accessTokenGenerator,
            refreshTokenGenerator
        );
    }

    @Bean
    public AuthenticationConverter authenticationConverter() {
        return request -> {
            String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
            if ("client_credentials".equals(grantType)) {
                return new OAuth2ClientCredentialsAuthenticationConverter().convert(request);
            } else if ("urn:ietf:params:oauth:grant-type:token-exchange".equals(grantType)) {
                return new IdTokenAuthenticationConverter().convert(request);
            }
            return null;
        };
    }


}