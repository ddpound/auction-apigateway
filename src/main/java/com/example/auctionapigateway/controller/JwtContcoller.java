package com.example.auctionapigateway.controller;

import com.example.auctionapigateway.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RequiredArgsConstructor
@Log4j2
@RestController
public class JwtContcoller {

    private final JwtService jwtService;

    @GetMapping(value = "check")
    public String ControllerCkeck(){

        return "check controller";
    }

    /**
     * 저장할 토큰을 먼저 검증하고 verify가 통과한다면
     * 수정과 저장을 진행합니다.
     *
     * */
    @RequestMapping(value = "saveCheckToken", method = RequestMethod.POST, produces = "application/json; charset=utf8")
    public String saveCheckToken(@RequestBody Map<String,Object> body){


        int resultNum = jwtService.saveCheckTokenRepository(body);

        //System.out.println(resultNum);

        return "success token";
    }
}
