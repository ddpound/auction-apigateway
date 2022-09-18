package com.example.auctionapigateway.filterconfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;


@Configuration
public class CorsConfig {

    // 스프링 시큐리티가 들고있는 cors 필터입니다.
    // 프론트쪽에서 계속 막힌게 이녀석 때문
    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration config = new CorsConfiguration();

        // 내 서버 데이터 응답시 json을 자바 스크립트에서 처리할수 있도록
        config.setAllowCredentials(true);

        // 지금 코드가 위의 setAloowCredentials 와 같이 사용되는걸 권장한다
        config.addAllowedOriginPattern("*");
        // 재밌는 점은 아래 코드는 이제 위의 setAllowCredentials 와 함께 사용하는걸
        // 권장하지 않는다
        //config.addAllowedOrigin("*"); // 모든 ip 응답을 허용

        config.addAllowedHeader("*"); // 모든 헤더의 응답을 허용
        config.addAllowedMethod("*"); // 모든 post,get 등등의 메소드들을 허용
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}

