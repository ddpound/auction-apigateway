package com.example.auctionapigateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.modulecommon.jwtutil.JWTUtil;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;


@Component
@Log4j2
public class JwtCookieFilter extends AbstractGatewayFilterFactory<JwtCookieFilter.Config> {

    private final JWTUtil jwtUtil;

    private final String JWT_COOKIE_NAME;

    private final String REFRESH_COOKIE_NAME;

    private final String JWT_COOKIE_ID;

    public static class Config{}
    public JwtCookieFilter(JWTUtil jwtUtil, Environment env) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
        JWT_COOKIE_NAME = env.getProperty("myToken.cookieJWTName");
        REFRESH_COOKIE_NAME = env.getProperty("myToken.refreshJWTCookieName");
        JWT_COOKIE_ID = env.getProperty("myToken.userId");

    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            log.info("JwtCookieFilter works.");
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            try {
                // JWT 토큰을 HttpOnly 쿠키에서 가져옵니다.
                Map<String, String> tokens = getTokenFromCookie(request);

                if(Objects.requireNonNull(tokens).isEmpty()){
                    return onError(exchange,"Sorry, cookies token null ", HttpStatus.UNAUTHORIZED);
                }

                if (StringUtils.hasText(tokens.get(JWT_COOKIE_NAME))) {



                    // JWT 토큰에서 사용자 정보를 가져옵니다.
                    Map<Integer, DecodedJWT> resultMapToken = jwtUtil
                            .returnMapMyTokenVerify(tokens.get(JWT_COOKIE_NAME),Integer.parseInt(tokens.get(JWT_COOKIE_ID)));


                    if(resultMapToken.containsKey(1)){
                        log.info("success verify token");
                        return chain.filter(exchange);
                    }

                    // -1 즉 토큰 검증이 실패했을 때
                    if(resultMapToken.containsKey(-1)){
                        return onError(exchange,"[API GATEWAY] Token authentication failed.", HttpStatus.UNAUTHORIZED);
                    }

                    // -2 만료, 리프레시 토큰의 상태를 체크하고 새로운 값을 넣어야함
                    if(resultMapToken.containsKey(-2)){
                        resultMapToken = jwtUtil.returnMapMyTokenVerify(tokens.get(REFRESH_COOKIE_NAME),Integer.parseInt(tokens.get(JWT_COOKIE_ID)));

                        if(resultMapToken.containsKey(-1)){
                            return onError(exchange,"refresh Token fail verify", HttpStatus.UNAUTHORIZED);
                        }

                        // 여기서 만약 또 리프레시마저 만료라면 재 로그인 시도를 유도해야함
                        if(resultMapToken.containsKey(-2)){
                            return onError(exchange,"API GATEWAY The RefreshToken has expired, try relogin", HttpStatus.FORBIDDEN);
                        }

                        // 리프레시가 검증 완료라면 새 토큰을 만들어주자
                        if(resultMapToken.containsKey(1)){
                            HttpCookie cookie = request.getCookies().getFirst(JWT_COOKIE_NAME);
                            if (cookie != null) {
                                // 쿠키 생성
                                ResponseCookie newCookie = ResponseCookie.from(JWT_COOKIE_NAME,
                                                jwtUtil.makeAuthToken(JWT.decode(cookie.getValue()).getClaim("userId").asInt()))
                                        .path("/")
                                        .maxAge(Duration.ofDays(7))
                                        .httpOnly(true)
                                        .secure(false)
                                        .build();
                                // 변경된 쿠키를 다시 응답 헤더에 추가합니다.
                                response.addCookie(newCookie);
                                log.info("success checkfilter and new Token making");
                                return chain.filter(exchange);
                            }
                        }
                    }

                    return onError(exchange,"Sorry, an unknown error ", HttpStatus.UNAUTHORIZED);
                }
            }catch (Exception e){
                log.error("Error failed: " + e);
                return onError(exchange,"Filter Error", HttpStatus.FORBIDDEN);
            }
            return onError(exchange,"Filter Error", HttpStatus.FORBIDDEN);
        });

    }

    private Map<String, String> getTokenFromCookie(ServerHttpRequest request) {
        Map<String, String> returnHashMap = new HashMap<>();

        HttpCookie cookie = request.getCookies().getFirst(JWT_COOKIE_NAME);
        HttpCookie Refreshcookies = request.getCookies().getFirst(REFRESH_COOKIE_NAME);
        HttpCookie userIdCookie = request.getCookies().getFirst(JWT_COOKIE_ID);

        System.out.println("내가만큰쿠키");
        System.out.println(request);
        System.out.println(request.getHeaders().values());
        System.out.println(request.getMethod());
        System.out.println(request.getCookies());

        System.out.println("쿠키 타겟팅");
        System.out.println(cookie);
        System.out.println(Refreshcookies);


        if (cookie != null) {

            returnHashMap.put(JWT_COOKIE_NAME, cookie.getValue());

            if (Refreshcookies != null) {
                returnHashMap.put(REFRESH_COOKIE_NAME, Refreshcookies.getValue());
            }

            if (userIdCookie != null) {
                returnHashMap.put(JWT_COOKIE_ID, userIdCookie.getValue());
            }

            return returnHashMap;
        }

        return null;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errMassage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(errMassage);
        return response.setComplete();
    }



}
