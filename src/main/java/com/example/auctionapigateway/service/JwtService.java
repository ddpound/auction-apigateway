package com.example.auctionapigateway.service;

import com.example.auctionapigateway.model.JwtSuperintendModel;
import com.example.auctionapigateway.repository.JwtSuperintendRepository;


import com.example.modulecommon.jwtutil.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Log4j2
@RequiredArgsConstructor
@Service
public class JwtService {

    private final JwtSuperintendRepository jwtSuperintendRepository;

    private final JWTUtil jwtUtil;



    @Transactional
    public int saveCheckTokenRepository(Map<String,Object> body){

        JwtSuperintendModel findJwtSuperintendModel = jwtSuperintendRepository.findByUsername((body.get("username").toString().replaceAll("[\\[|\\]]","")));

        String token =  String.valueOf(body.get("mytoken")).replaceAll("[\\[|\\]]","");
        String refreshToken = String.valueOf(body.get("RefreshToken")).replaceAll("[\\[|\\]]","");
        String servertoken =  String.valueOf(body.get("ServerToken")).replaceAll("[\\[|\\]]","");

        log.info("SAVECHCEKTOKEN TRY LOGIN");

        if (token.length() == 0  || refreshToken.length() == 0 || servertoken.length() == 0){
            return -1;
        }else{

            // JWT 인증 받으면 바로 통과시켜서 저장시켜줌
            if(jwtUtil.serverJWTTokenVerify(servertoken)){

                if(findJwtSuperintendModel != null ){

                    // 이미 있는거니깐 수정, 더티체킹
                    findJwtSuperintendModel.setAccessToken(token);
                    findJwtSuperintendModel.setRefreshToken(refreshToken);
                    log.info("changeToken");
                    return 2; // 수정을 뜻함

                }else{
                    // 처음이라면 새로저장
                    JwtSuperintendModel jwtSuperintendModel = JwtSuperintendModel.builder()
                            .username(body.get("username").toString().replaceAll("[\\[|\\]]",""))
                            .accessToken(token)
                            .refreshToken(refreshToken)
                            .build();

                    jwtSuperintendRepository.save(jwtSuperintendModel);
                }



                return 1;
            }

           return -2;
        }


    }

}
