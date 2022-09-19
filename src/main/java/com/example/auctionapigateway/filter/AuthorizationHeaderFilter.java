package com.example.auctionapigateway.filter;

import lombok.extern.log4j.Log4j2;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

@Log4j2
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter> {

    public AuthorizationHeaderFilter(){

    }

    public static class Config{

    }

    @Override
    public GatewayFilter apply(AuthorizationHeaderFilter config) {
        return null;
    }
}
