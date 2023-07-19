package com.salesmanager.shop.store.security;

public interface KeyCloakTokenService {
    Boolean validateToken(String token);

    String getUsernameFromToken(String token);

    String getJwkUrl();
}
