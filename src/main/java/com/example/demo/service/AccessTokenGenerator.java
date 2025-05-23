// package com.example.demo.service;
//
// import org.springframework.stereotype.Service;
//
// import java.time.Instant;
// import java.util.List;
//
// @Service
// public class AccessTokenGenerator {
//
//     private final Algorithm algorithm;
//
//     public AccessTokenGenerator() {
//         // 用對稱金鑰 (HMAC SHA256)
//         this.algorithm = Algorithm.HMAC256("your-very-secret-key");
//     }
//
//     public String generate(String subject, List<String> roles) {
//         Instant now = Instant.now();
//         return JWT.create()
//                 .withSubject(subject)
//                 .withClaim("roles", roles)
//                 .withIssuedAt(Date.from(now))
//                 .withExpiresAt(Date.from(now.plusSeconds(3600)))
//                 .sign(algorithm);
//     }
// }
