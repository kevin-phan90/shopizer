package com.salesmanager.shop.store.security;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

@Component
public class KeyCloakTokenUtil implements Serializable {

    @Value("${keycloak.jwk-set-uri:http://localhost:8180/realms/ecommerce-backoffice/protocol/openid-connect/certs}")
    private String jwkUrl;


    public Boolean validateToken(String token) {
        try {
            String kid = JwtHelper.headers(token).get("kid");
            final Jwt tokenDecoded = JwtHelper.decodeAndVerify(token, verifier(kid));
            //final Map<String, String> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);
            return true;
        } catch (Exception ex) {
            System.out.println(ex);
        }

        return false;
    }

    public String getUsernameFromToken(String token) {
        try {
            final Jwt tokenDecoded = JwtHelper.decode(token);
            final Map<String, String> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);
            return authInfo.get("email");
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return null;
    }

    private RsaVerifier verifier(String kid) throws Exception {
        JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
        Jwk jwk = provider.get(kid);
        return new RsaVerifier((RSAPublicKey) jwk.getPublicKey());
    }
}
