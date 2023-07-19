package com.salesmanager.shop.application.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class IDPConfiguration {
    @Value("${keycloak.backoffice.jwk-set-uri:http://localhost:8180/realms/ecommerce-backoffice/protocol/openid-connect/certs}")
    private String backofficeJwkUrl;

    @Value("${keycloak.customer.jwk-set-uri:http://localhost:8180/realms/ecommerce-customer/protocol/openid-connect/certs}")
    private String customerJwkUrl;

    public String getBackofficeJwkUrl() {
        return backofficeJwkUrl;
    }

    public String getCustomerJwkUrl() {
        return customerJwkUrl;
    }
}
