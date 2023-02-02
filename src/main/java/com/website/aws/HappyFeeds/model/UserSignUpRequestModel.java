package com.website.aws.HappyFeeds.model;

import lombok.Getter;

@Getter
public class UserSignUpRequestModel {
    private String email;
    private String password;
    private String firstName;
    private String lastName;
}
