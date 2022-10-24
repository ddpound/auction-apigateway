package com.example.auctionapigateway.repository;


import com.example.auctionapigateway.model.JwtSuperintendModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface JwtSuperintendRepository extends JpaRepository<JwtSuperintendModel,Integer> {

    JwtSuperintendModel findByUsername(String user);


    JwtSuperintendModel findByAccessTokenAndRefreshToken(String accessToken, String refreshToken);



    void deleteByUsername(String user);

    @Transactional
    @Modifying
    @Query("update JwtSuperintendModel set accessToken = :accessToken, " +
            "refreshToken = :refreshToken , modifyToken = current_timestamp where username = :user")
    void updateAcTokenRefreshToken(@Param("accessToken")String accessToken,
                                   @Param("refreshToken")String refreshToken,
                                   @Param("user") String user);


    @Transactional
    @Modifying
    @Query("update JwtSuperintendModel set accessToken = :accessToken," +
            "modifyToken = current_timestamp where username = :user")
    void updateAcToken(@Param("accessToken")String accessToken,
                       @Param("user") String user);
}