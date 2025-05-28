package com.example.demo;

import com.example.demo.entity.ClientEntity;
import com.example.demo.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class DataInitializer {

    private final ClientRepository clientRepository;
    private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Bean
    public CommandLineRunner initData() {
        return args -> {
            // 初始化 Client
            if (clientRepository.findByClientId("sample_client_id").isEmpty()) {
                ClientEntity clientEntity = new ClientEntity();
                clientEntity.setId(UUID.randomUUID().toString());
                clientEntity.setClientId("sample_client_id");
                clientEntity.setClientSecret(encoder.encode("sample_client_secret"));
                clientEntity.setAuthorizationGrantTypes("client_credentials");
                clientEntity.setScopes("read,write");

                clientRepository.save(clientEntity);
            }
        };
    }
}