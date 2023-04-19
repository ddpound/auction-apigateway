package com.example.auctionapigateway.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.modulecommon.jwtutil.JWTUtil;
import lombok.extern.log4j.Log4j2;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
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

    public static class Config{}
    public JwtCookieFilter(JWTUtil jwtUtil, Environment env) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
        //JWT_COOKIE_NAME = env.getProperty("jwt.cookieName");
        JWT_COOKIE_NAME = "token";
        REFRESH_COOKIE_NAME = "refreshtoken";
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

                if (StringUtils.hasText(tokens.get(JWT_COOKIE_NAME))) {
                    // JWT 토큰에서 사용자 정보를 가져옵니다.
                    Map<Integer, DecodedJWT> resultMapToken = jwtUtil.returnMapMyTokenVerify(tokens.get(JWT_COOKIE_NAME));
                    return chain.filter(exchange);
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

        HttpHeaders headers = request.getHeaders();
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

    private Mono<Void> onError(ServerWebExchange exchange, String errMassage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(errMassage);
        return response.setComplete();
    }



}
