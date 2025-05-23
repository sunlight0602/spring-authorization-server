package com.example.demo;

import com.example.demo.entity.Client;
import com.example.demo.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;
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
                Client client = new Client();
                client.setId(UUID.randomUUID().toString());
                client.setClientId("sample_client_id");
                client.setClientSecret(encoder.encode("sample_client_secret"));
                client.setAuthorizationGrantTypes("client_credentials");
                client.setScopes("read,write");

                clientRepository.save(client);
            }
        };
    }
}