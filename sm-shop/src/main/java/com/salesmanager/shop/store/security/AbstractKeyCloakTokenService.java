package com.salesmanager.shop.store.security;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;


public abstract class AbstractKeyCloakTokenService implements KeyCloakTokenService{


    //private String jwkUrl;


    @Override
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

    @Override
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
        JwkProvider provider = new UrlJwkProvider(new URL(getJwkUrl()));
        Jwk jwk = provider.get(kid);
        return new RsaVerifier((RSAPublicKey) jwk.getPublicKey());
    }




}
