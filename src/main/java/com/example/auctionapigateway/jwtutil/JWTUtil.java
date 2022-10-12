package com.example.auctionapigateway.jwtutil;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

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

    /**
     * 키와 밸류 형식으로 한번에 해주기
     *  1이면 검증완료, -2 이면 만료된 토큰, -1 이면 검증실패, 그냥 토큰이 검증실패
     * */
    public Map<Integer, DecodedJWT> returnMapMyTokenVerify(String token){
        Map<Integer,DecodedJWT> returnMap = new HashMap<>();

        try {
            DecodedJWT verify = JWT.require(Algorithm.HMAC256(myKey)).build().verify(token);
            log.info("success myToken verify");
            returnMap.put(1, verify);
            return returnMap;
        }catch (TokenExpiredException e){
            log.info("The myToken has expired"); // 토큰 유효시간이 지남

            DecodedJWT decodeJWT = JWT.decode(token);
            returnMap.put(-2, decodeJWT);

            // 재발급이 필요, 리프레시 토큰이 있나 체크해야함
            return returnMap;
        }

        catch (Exception e){
            //e.printStackTrace();
            DecodedJWT decodeJWT = JWT.decode(token);

            log.info("myToken fail verify : " + decodeJWT);
            // 실패시
            returnMap.put(-1, decodeJWT);
            return returnMap;

        }
    }

}
