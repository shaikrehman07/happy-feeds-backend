package com.website.aws.HappyFeeds.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserLoginResponseModel {

    private String name;
    private String email;
    private int statusCode;
    private boolean isSuccessful;
}
