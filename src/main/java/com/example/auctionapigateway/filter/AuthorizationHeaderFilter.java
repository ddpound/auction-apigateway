package com.example.auctionapigateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.auctionapigateway.repository.JwtSuperintendRepository;

import com.example.modulecommon.jwtutil.JWTUtil;
import lombok.extern.log4j.Log4j2;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;


import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;


import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
@Log4j2
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final JWTUtil jwtUtil;

    private final JwtSuperintendRepository jwtSuperintendRepository;

    private final String JWT_COOKIE_NAME;

    private final String REFRESH_COOKIE_NAME;

    public static class Config{}

    @Autowired
    public AuthorizationHeaderFilter(JWTUtil jwtUtil,
                                     JwtSuperintendRepository jwtSuperintendRepository){
        super(Config.class);
        this.jwtUtil = jwtUtil;
        this.jwtSuperintendRepository = jwtSuperintendRepository;
        JWT_COOKIE_NAME = "token";
        REFRESH_COOKIE_NAME = "refreshtoken";
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();




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

                // 쿠키 추가부분
                try {
                    Map<String, String> tokens = getTokenFromCookie(request);
                    System.out.println("쿠키토큰 결과값");
                    System.out.println(tokens.get(JWT_COOKIE_NAME));
                    System.out.println(tokens.get(REFRESH_COOKIE_NAME));
                    System.out.println(tokens.values());
                }catch (Exception e){
                    log.error(e);
                }

                String jwtHeader = autorizationHeader.replace("Bearer ","");
                reFreshJwtHeader = reFreshJwtHeader.replace("Bearer ", "");

                // 1일때 검증완료, -2 면 토큰 만료
                // 이렇게 담아두면 다시 재 검증할 필요가 없음
                Map<Integer, DecodedJWT> resultMapToken = jwtUtil.returnMapMyTokenVerify(jwtHeader);

                // -1 즉 토큰 검증이 실패했을 때
                if(resultMapToken.containsKey(-1)){
                    return onError(exchange,"[API GATEWAY] Token authentication failed.", HttpStatus.UNAUTHORIZED);
                }


                // -2 즉 만료일 때, 리프레시 토큰을 체크하고 새로운 값을 넣어줘야함
                if(resultMapToken.containsKey(-2)){
                    // 리프레시 토큰 검증 시작, 값 변경
                    resultMapToken = jwtUtil.returnMapMyTokenVerify(reFreshJwtHeader);

                    // 리프레시 토큰값이 유효하다면
                    if(resultMapToken.containsKey(1)){

                        // 리프레시 토큰이라면 이게 있을것이다
                        if(resultMapToken.get(1).getClaim("refresh").asString() != null){

                            // 리프레시 토큰, 액세스 토큰 다 DB검색
                            // 디비에 한쌍으로 검색, 만약 없다면 누가 탈취해서 임의로 값을 넣은걸 의심
                            String findUsername;
                            try{
                                findUsername = jwtSuperintendRepository.findByAccessTokenAndRefreshToken(jwtHeader,reFreshJwtHeader).getUsername();
                            }catch (NullPointerException e){
                                log.error(e);
                                return onError(exchange,"db not found token,refreshToken fail filter Check", HttpStatus.FORBIDDEN);
                            }

                            String newAccessToken = jwtUtil.makeAuthToken(findUsername, JWT.decode(jwtHeader).getClaim("userId").asInt());

                            log.info("api gateway JWT FILTER , REFRESH TOKEN EXPIRED AND NEW MAKE TOKEN");

                            response.getHeaders().add(HttpHeaders.AUTHORIZATION,"Bearer "+ newAccessToken);
                            response.getHeaders().add("RefreshToken","Bearer "+ reFreshJwtHeader);

                            // 여기서 새로운 토큰을 만들어주고 새로 생성
                            jwtSuperintendRepository
                                    .updateAcToken(
                                            newAccessToken,
                                            findUsername
                                    );
                            resultMapToken = jwtUtil.returnMapMyTokenVerify(newAccessToken);

                            log.info("success checkfilter and new Token making : " +  findUsername);
                            return chain.filter(exchange);
                        }
                    }
                    // 여기서 만약 또 리프레시마저 만료라면 재 로그인 시도를 유도해야함
                    if(resultMapToken.containsKey(-2)){
                        return onError(exchange,"API GATEWAY The RefreshToken has expired", HttpStatus.FORBIDDEN);
                    }
                }else if(resultMapToken.containsKey(1)) {
                    //만료가 아니고 값이 잘 들어왔다면
                    // 문제 없이 여기까지왔다면 통과
                    log.info("[AuthorizationHeader Filter] This Token is success Authorization");
                    return chain.filter(exchange);

                }

                return onError(exchange,"Filter Error", HttpStatus.FORBIDDEN);

            }

            return onError(exchange,"Filter Error", HttpStatus.FORBIDDEN);
        });
    }

    // Mono, Flux -> Spring WebFlux 라는 것
    private Mono<Void> onError(ServerWebExchange exchange, String errMassage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(errMassage);
        return response.setComplete();
    }

    private Map<String, String> getTokenFromCookie(ServerHttpRequest request) {
        Map<String, String> returnHashMap = new HashMap<>();

        org.springframework.http.HttpHeaders headers = request.getHeaders();
        List<String> JWTcookes = headers.get("Cookie");

        HttpCookie cookie = request.getCookies().getFirst(JWT_COOKIE_NAME);
        HttpCookie Refreshcookies = request.getCookies().getFirst(REFRESH_COOKIE_NAME);

        System.out.println("내가만든ㄱ쿠키~");
        System.out.println(request);
        System.out.println(request.getHeaders().values());
        System.out.println(request.getMethod());
        System.out.println(request.getCookies());
        System.out.println();
        request.getCookies().values().stream()
                .map(httpCookies -> {
                    return httpCookies.stream().map(httpCookie -> {
                        String cookieName = httpCookie.getName();
                        String cookieValue = cookie.getValue();
                        System.out.println("회전값 작동 유무");
                        System.out.println(cookieName);
                        System.out.println(cookieValue);
                        return null;
                    });
                });

        System.out.println(Objects.requireNonNull(cookie).getValue());
        System.out.println(Objects.requireNonNull(Refreshcookies).getValue());


        if (cookie != null) {

            returnHashMap.put(JWT_COOKIE_NAME, cookie.getValue());

            if (Refreshcookies != null) {
                returnHashMap.put(REFRESH_COOKIE_NAME, Refreshcookies.getValue());
            }

            return returnHashMap;
        }

        return null;
    }

}
