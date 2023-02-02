package com.website.aws.HappyFeeds.controller;

import com.website.aws.HappyFeeds.exception.TokenException;
import com.website.aws.HappyFeeds.model.*;
import com.website.aws.HappyFeeds.service.AWSService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api")
public class FeedsController {

    @Autowired
    private AWSService awsService;

    @GetMapping(value = "/", consumes = "text/plain")
    public String hello(@RequestBody String name) {
        return "Hello " + name;
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> uploadFile(@RequestParam("email") String userEmail, @RequestPart(value = "File") MultipartFile file, @RequestPart(value = "caption", required = false) String caption, @RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");

        caption = caption == null ? "no value" : caption;
        return new ResponseEntity<>(awsService.upload(userEmail, file, caption), HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<UserLoginResponseModel> login(@RequestBody UserLoginRequestModel loginDetails) {


        UserLoginResponseModel loginResponse = awsService.loginUser(loginDetails);
        HttpHeaders responseHeaders = awsService.headers();

        return ResponseEntity.ok().headers(responseHeaders).body(loginResponse);
    }

    @PostMapping("/signup")
    public ResponseEntity<UserSignUpResponseModel> signup(@RequestBody UserSignUpRequestModel signupDetails) {
        UserSignUpResponseModel signupResponse = awsService.createUser(signupDetails);

        return ResponseEntity.ok().body(signupResponse);
    }

    @GetMapping("/photos")
    public ResponseEntity<List<String>> getPhotos(@RequestParam("email") String email, @RequestHeader("AccessToken") String accessToken) throws TokenException {
        //token validation
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");

        return ResponseEntity.ok().body(awsService.getAllUserPhotos(email));
    }

    @GetMapping("/users/{name}")
    public ResponseEntity<List<UserSearchModel>> getSearUserList(@PathVariable String name, @RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");

        return ResponseEntity.ok().body(awsService.getSearchUserList(name));
    }

    @GetMapping("/{currentUserEmail}/user/{otherUserEmail}")
    public ResponseEntity<OtherUserProfile> getotherUserDetails(@PathVariable("otherUserEmail") String otherUserEmail, @PathVariable("currentUserEmail") String currentUserEmail, @RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");

        return ResponseEntity.ok().body(awsService.otherUserDetails(otherUserEmail, currentUserEmail));
    }

    @PostMapping("/friend/{otherUserEmail}/{currentUserEmail}")
    public ResponseEntity<String> sendRequest(@PathVariable("otherUserEmail") String otherUserEmail, @PathVariable("currentUserEmail") String currentUserEmail, @RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");

        return ResponseEntity.ok().body(awsService.sendRequest(otherUserEmail, currentUserEmail));
    }

    @PostMapping("/accept/{otherUserEmail}/{currentUserEmail}")
    public ResponseEntity<String> acceptRequest(@PathVariable("otherUserEmail") String otherUserEmail, @PathVariable("currentUserEmail") String currentUserEmail,@RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");

        return ResponseEntity.ok().body(awsService.acceptRequest(otherUserEmail, currentUserEmail));
    }

    @GetMapping("/{currentUserEmail}/friends")
    public List<String> getStatusWithFriends(@PathVariable("currentUserEmail") String currentUserEmail,@RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");
        return awsService.getFriends(currentUserEmail, "Friends");
    }

    @GetMapping("/{currentUserEmail}/sentRequest")
    public ResponseEntity<List<String>> getStatusWithSent(@PathVariable("currentUserEmail") String currentUserEmail,@RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");

        return ResponseEntity.ok().body(awsService.getFriends(currentUserEmail, "Accept Request"));
    }

    @GetMapping("/{currentUserEmail}/receivedRequest")
    public ResponseEntity<List<String>> getStatusWithReceived(@PathVariable("currentUserEmail") String currentUserEmail,@RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");

        return ResponseEntity.ok().body(awsService.getFriends(currentUserEmail, "Request Sent"));
    }

    @PostMapping(value = "/uploadDP", consumes = "text/plain")
    public ResponseEntity<String> uploadDP(@RequestParam("email") String userEmail, @RequestBody String file,@RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");
        return new ResponseEntity<>(awsService.uploadDP(userEmail, file), HttpStatus.OK);
    }

    @GetMapping("/userProfile")
    public ResponseEntity<UserProfile> getUserProfile(@RequestParam("email") String userEmail,@RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");
        return ResponseEntity.ok().body(awsService.getUserProfile(userEmail));
    }

    @GetMapping("/feeds")
    public ResponseEntity<UserHome> getUserFeeds(@RequestParam("email") String userEmail,@RequestHeader("AccessToken") String accessToken) throws TokenException {
        boolean tokenValid = awsService.verifyJWT(accessToken);
        if (!tokenValid) throw new TokenException("Token not valid");
        return ResponseEntity.ok().body(awsService.getUserHome(userEmail));
    }

}

