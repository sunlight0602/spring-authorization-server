package com.example.demo.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "client")
@Data
public class ClientEntity {
    @Id
    private String id;
    private String clientId;
    private String clientSecret;

    // 先簡化
    // private Instant clientIdIssuedAt;
    // private Instant clientSecretExpiresAt;
    // private String clientName;
    // @Column(length = 1000)
    // private String clientAuthenticationMethods;
    // @Column(length = 100)
    // private String authorizationGrantTypes;
    // @Column(length = 1000)
    // private String redirectUris;
    // @Column(length = 1000)
    // private String postLogoutRedirectUris;
    @Column(length = 200)
    private String scopes;
    // @Column(length = 2000)
    // private String clientSettings;
    // @Column(length = 2000)
    // private String tokenSettings;
}
