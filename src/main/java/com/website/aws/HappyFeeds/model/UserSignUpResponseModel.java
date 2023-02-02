package com.website.aws.HappyFeeds.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserSignUpResponseModel {
    private boolean isSuccessful;
    private int statusCode;
    private String cognitoUserID;
    private boolean isConfirmed;
}
