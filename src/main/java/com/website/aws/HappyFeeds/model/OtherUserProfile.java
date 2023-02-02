package com.website.aws.HappyFeeds.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class OtherUserProfile {

    private String name;
    private String email;
    private int friendsCount;
    private byte[] userDP;
    private List<String> userPhotos;
    private String friendStatus;
}
