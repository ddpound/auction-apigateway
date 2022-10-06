package com.example.auctionapigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.trace.http.HttpTraceRepository;
import org.springframework.boot.actuate.trace.http.InMemoryHttpTraceRepository;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication(scanBasePackages = {"com.example.auctionapigateway","com.example.modulecommon"})
public class AuctionApigatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuctionApigatewayApplication.class, args);
    }

    @Bean
    public HttpTraceRepository httpTraceRepository(){
        return new InMemoryHttpTraceRepository();

    }

}
