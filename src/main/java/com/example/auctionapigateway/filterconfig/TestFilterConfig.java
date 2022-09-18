package com.example.auctionapigateway.filterconfig;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TestFilterConfig {

    @Bean
    public RouteLocator gateTestRoutes(RouteLocatorBuilder builder){

        return builder.routes()
                .route(r -> r.path("/first-test-service/**")
                             .filters(f-> f.addRequestHeader("test","this header is test request"))
                             .uri("lb://first-test-service"))
                .build();
    }
}
