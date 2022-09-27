package com.example.auctionapigateway.jwtutil;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.time.Instant;

import com.example.modulecommon.model.UserModel;

@Log4j2
@Getter
@Component
public class JWTUtil {

    @Value("{myToken.userSecretKey}")
    private String userSecretKey;

    // @Value 는 정적 변수로는 담지 못함
    // 토큰 검증에 필요한 키
    @Value("${myToken.myKey}")
    private String myKey;

    @Value("${tokenVerifyTime.accesstimeSet}")
    private long AUTH_TIME;

    @Value("${tokenVerifyTime.refreshTimeSet}")
    private long REFRESH_TIME;

    /**
     * 토큰 제작 메소드
     *
     * */
    public String makeAuthToken(UserModel user){
        log.info("now New make Token : " + user.getUsername());
        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuer("nowAuction")
                .withClaim("username", user.getUsername()) // 유저이름
                .withClaim("userRole",user.getRoleList())
                .withClaim("exp", Instant.now().getEpochSecond()+AUTH_TIME)
                .sign(Algorithm.HMAC256(myKey));

        // EpochSecond 에폭세컨드를 이용해 exp이름을 붙여 직접 시간을 지정해준다
    }

    /**
     * 유저네임을 넣은 Refresh  Token
     *
     * */
    public String makeRfreshToken(UserModel user){
        log.info("now New make refresh Token : " + user.getUsername());
        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuer("nowAuction")
                .withClaim("refresh","refresh")
                .withClaim("exp", Instant.now().getEpochSecond()+REFRESH_TIME)
                .sign(Algorithm.HMAC256(myKey));

        // EpochSecond 에폭세컨드를 이용해 exp이름을 붙여 직접 시간을 지정해준다
        // 만료시간은 리프레쉬 토큰 시간에 맞춰서 넣는다
    }

}
