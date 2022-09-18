package com.example.auctionapigateway.filterconfig;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


/**
 * 해당 설정 파일은 유저에 관한 게이트 파일입니다.
 *
 * */
@Configuration
public class UserFilterConfig {

    @Bean
    public RouteLocator gateUserRoutes(RouteLocatorBuilder builder){

        return builder.routes()
                .route(r -> r.path("/auction-user/join/**")
                        .filters(f-> f.rewritePath("/auction-user/(?<segment>.*)","/$\\{segment}")
                                .removeRequestHeader("Cookie"))
                        .uri("lb://auction-user"))
                .route(r -> r.path("/auction-user/login/**")
                        .filters(f-> f.rewritePath("/auction-user/(?<segment>.*)","/$\\{segment}")
                                .removeRequestHeader("Cookie"))
                        .uri("lb://auction-user"))
                .route(r -> r.path("/auction-user/**")
                        .filters(f-> f.rewritePath("/auction-user/(?<segment>.*)","/$\\{segment}")
                                .removeRequestHeader("Cookie"))
                        .uri("lb://auction-user"))
                .build();
    }
}
