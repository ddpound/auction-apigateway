package com.example.auctionapigateway.filter;

import lombok.extern.log4j.Log4j2;
import org.apache.http.HttpHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;

import org.springframework.http.HttpStatus;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Log4j2
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter> {

    public AuthorizationHeaderFilter(){

    }

    public static class Config{

    }

    @Override
    public GatewayFilter apply(AuthorizationHeaderFilter config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange,"no authorization header", HttpStatus.UNAUTHORIZED);
            }

            String autorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

            String jwtHeader = autorizationHeader.replace("Bearer","");

            // 작동 테스트 바람
            String reFreshJwtHeader = request.getHeaders().get("RefreshToken").get(0);

            if(jwtHeader == null || !jwtHeader.startsWith("Bearer")
                    || reFreshJwtHeader == null || !reFreshJwtHeader.startsWith("Bearer")){
                log.info("This request have not token");
            }else{

            }

            log.info("API GATEWAY JWTCheckFilter has been activated.");





            return chain.filter(exchange);
        });
    }

    // Mono, Flux -> Spring WebFlux 라는 것
    private Mono<Void> onError(ServerWebExchange exchange, String errMassage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(errMassage);
        return response.setComplete();
    }
}
