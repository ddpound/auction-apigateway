package com.example.auctionapigateway.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.auctionapigateway.repository.JwtSuperintendRepository;
import com.example.modulecommon.jwtutil.JWTUtil;
import com.example.modulecommon.makefile.MakeFile;

import lombok.extern.log4j.Log4j2;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;


import org.springframework.http.HttpStatus;


import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
@Log4j2
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final JWTUtil jwtUtil;

    private final JwtSuperintendRepository jwtSuperintendRepository;

    public static class Config{}

    @Autowired
    public AuthorizationHeaderFilter(JWTUtil jwtUtil,
                                     JwtSuperintendRepository jwtSuperintendRepository){
        super(Config.class);
        this.jwtUtil = jwtUtil;
        this.jwtSuperintendRepository = jwtSuperintendRepository;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();


            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange,"no authorization header", HttpStatus.UNAUTHORIZED);
            }

            String autorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            // 작동 테스트 바람
            String reFreshJwtHeader = request.getHeaders().get("RefreshToken").get(0);


            if(!autorizationHeader.startsWith("Bearer") || !reFreshJwtHeader.startsWith("Bearer")){
                log.info("This request have not token");
            }else{
                log.info("API GATEWAY JWTCheckFilter has been activated.");

                String jwtHeader = autorizationHeader.replace("Bearer ","");
                reFreshJwtHeader = reFreshJwtHeader.replace("Bearer ", "");

                // 1일때 검증완료, -2 면 토큰 만료
                // 이렇게 담아두면 다시 재 검증할 필요가 없음
                Map<Integer, DecodedJWT> resultMapToken = jwtUtil.returnMapMyTokenVerify(jwtHeader);

                String username;

                // -2 즉 만료일 때
                if(resultMapToken.containsKey(-2)){
                    // 리프레시 토큰 검증 시작, 값 변경
                    resultMapToken = jwtUtil.returnMapMyTokenVerify(reFreshJwtHeader);

                }


                // 즉 1 인 key값이 있는지 체크,
                if(resultMapToken.containsKey(1)){

                    // 리프레쉬 과정중에 에러발생함 찾아내기

                    // 리프레시 토큰이라면 이게 있을것이다
                    if(resultMapToken.get(1).getClaim("refresh").asString() != null){

                        // 리프레시 토큰, 액세스 토큰 다 DB검색
                        // 디비에 한쌍으로 검색, 만약 없다면 누가 탈취해서 임의로 값을 넣은걸 의심
                        String findUsername = jwtSuperintendRepository.findByAccessTokenAndRefreshToken(jwtHeader,reFreshJwtHeader).getUsername();

                        String newAccessToken = jwtUtil.makeAuthToken(findUsername);

                        //리프레시까지 다시 재발급이아니라 액세스만 재발급해서 다시 DB한쌍에 저장
                        //String newRefreshToken = loginFilterJWTUtil.makeRfreshToken(userModel);

                        ServerHttpResponse response = exchange.getResponse();

//                        response.addHeader(HttpHeaders.AUTHORIZATION,"Bearer "+ newAccessToken);
//                        response.addHeader("RefreshToken","Bearer "+ reFreshJwtHeader);

                        jwtSuperintendRepository
                                .updateAcToken(
                                        newAccessToken,
                                        findUsername
                                );
                        resultMapToken = jwtUtil.returnMapMyTokenVerify(newAccessToken);
                    }

                    // claim 안에 refresh가 있는지 체크해주기

                    username  = resultMapToken.get(1).getClaim("username").asString();

                }
                // 여기서 만약 또 리프레시마저 만료라면 재 로그인 시도를 유도해야함
                if(resultMapToken.containsKey(-2)){
                    return onError(exchange,"API GATEWAY The token has expired", HttpStatus.UNAUTHORIZED);
                }

                // 문제 없이 여기까지왔다면 통과
                log.info("success check api gateway AuthorizationHeader Filter");
                return chain.filter(exchange);

            }

            return onError(exchange,"Filter Error", HttpStatus.UNAUTHORIZED);
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
