package com.example.auctionapigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {"com.example.auctionapigateway","com.example.modulecommon"})
public class AuctionApigatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuctionApigatewayApplication.class, args);
    }

}
