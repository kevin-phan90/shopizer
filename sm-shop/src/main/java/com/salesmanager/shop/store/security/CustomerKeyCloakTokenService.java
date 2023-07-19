package com.salesmanager.shop.store.security;

import com.salesmanager.shop.application.config.IDPConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service("customerKeyCloakTokenService")
public class CustomerKeyCloakTokenService extends AbstractKeyCloakTokenService {
    @Autowired
    private IDPConfiguration idpConfiguration;
    @Override
    public String getJwkUrl() {
        return idpConfiguration.getCustomerJwkUrl();
    }
}
