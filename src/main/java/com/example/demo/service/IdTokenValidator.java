// package com.example.demo.service;
//
// import io.jsonwebtoken.JwtException;
// import org.springframework.http.HttpStatus;
// import org.springframework.security.oauth2.jwt.Jwt;
// import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
// import org.springframework.stereotype.Service;
// import org.springframework.web.server.ResponseStatusException;
//
// @Service
// public class IdTokenValidator {
//
//     private final NimbusJwtDecoder jwtDecoder;
//
//     public IdTokenValidator() {
//         String jwksUrl = "https://tsso.example.com/.well-known/jwks.json";
//         this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwksUrl).build();
//     }
//
//     public Jwt validate(String idToken) {
//         try {
//             Jwt jwt = jwtDecoder.decode(idToken);
//
//             // 驗證必要欄位
//             if (!"https://tsso.example.com".equals(jwt.getIssuer().toString())) {
//                 throw new JwtException("Invalid issuer");
//             }
//             if (!jwt.getAudience().contains("your-client-id")) {
//                 throw new JwtException("Invalid audience");
//             }
//
//             return jwt;
//         } catch (JwtException e) {
//             throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid id_token", e);
//         }
//     }
// }
