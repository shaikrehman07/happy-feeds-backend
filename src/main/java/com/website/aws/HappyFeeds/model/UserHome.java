package com.website.aws.HappyFeeds.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class UserHome {
    private List<UserFeeds> userFeedsList;
    private int feeds;
    private int posts;
}
