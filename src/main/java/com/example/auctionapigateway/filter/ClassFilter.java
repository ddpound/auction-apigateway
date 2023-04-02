package com.example.auctionapigateway.filter;

import lombok.extern.log4j.Log4j2;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;


/**
 * 권한 마다 다른 비밀번호가 필요
 *
 * */
@Component
@Log4j2
public class ClassFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {




    @Override
    public GatewayFilter apply(AuthorizationHeaderFilter.Config config) {
        return null;
    }
}
