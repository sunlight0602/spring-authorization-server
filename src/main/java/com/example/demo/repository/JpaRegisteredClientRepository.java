package com.example.demo.repository;

import java.util.*;

import com.example.demo.entity.ClientEntity;
import com.example.demo.entity.UserEntity;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

// @Component
@Slf4j
public class JpaRegisteredClientRepository implements RegisteredClientRepository {
    private final ClientRepository clientRepository;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JpaRegisteredClientRepository(ClientRepository clientRepository, UserRepository userRepository) {
        Assert.notNull(clientRepository, "clientRepository cannot be null");
        this.clientRepository = clientRepository;
        this.userRepository = userRepository;

        ClassLoader classLoader = JpaRegisteredClientRepository.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        // Assert.notNull(registeredClient, "registeredClient cannot be null");
        // this.clientRepository.save(toEntity(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        return null;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        // 先查 ServiceAccount
        Optional<ClientEntity> clientEntity = clientRepository.findByClientId(clientId);
        if (clientEntity.isPresent()) {
            return convertClientToRegisteredClient(clientEntity.get());
        }

        // 再查 User
        Optional<UserEntity> userEntity = userRepository.findByUserAccount(clientId);
        if (userEntity.isPresent()) {
            return convertUserToRegisteredClient(user.get());
        }

        return null;
    }

    private RegisteredClient convertClientToRegisteredClient(ClientEntity clientEntity) {
        Set<String> clientScopes = StringUtils.commaDelimitedListToSet(
                clientEntity.getScopes());
        Set<String> grantTypes = new HashSet<>();
        grantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());

        RegisteredClient.Builder builder = RegisteredClient.withId(clientEntity.getId())
                .clientId(clientEntity.getClientId())
                .clientSecret(clientEntity.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:token-exchange"))
                .scopes((scopes) -> scopes.addAll(clientScopes));

        return builder.build();
    }

    private RegisteredClient convertUserToRegisteredClient(UserEntity userEntity) {
        Set<String> userScopes = StringUtils.commaDelimitedListToSet(
                userEntity.getScopes());
        Set<String> grantTypes = new HashSet<>();
        grantTypes.add("urn:ietf:params:oauth:grant-type:token-exchange");

        RegisteredClient.Builder builder = RegisteredClient.withId(userEntity.getId())
                .clientId(userEntity.getUserAccount())
                .authorizationGrantTypes(grants -> {
                    grantTypes.forEach(grant -> grants.add(new AuthorizationGrantType(grant)));
                })
                .scopes((scopes) -> scopes.addAll(userScopes));

        return builder.build();
    }

    private ClientEntity convertRegisteredClientToClient(RegisteredClient registeredClient) {
        ClientEntity clientEntity = new ClientEntity();
        clientEntity.setId(registeredClient.getId());
        clientEntity.setClientId(registeredClient.getClientId());
        clientEntity.setClientSecret(registeredClient.getClientSecret());
        clientEntity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));

        return clientEntity;
    }

    private UserEntity convertRegisteredClientToUser(RegisteredClient registeredClient) {
        UserEntity userEntity = new UserEntity();
        userEntity.setId(registeredClient.getId());
        userEntity.setUserAccount(registeredClient.getClientId());
        userEntity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));

        return userEntity;
    }
}
