package com.website.aws.HappyFeeds.service;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.website.aws.HappyFeeds.awsconfig.AWSConfiguration;
import com.website.aws.HappyFeeds.awsconfig.AwsCognitoRSAKeyProvider;
import com.website.aws.HappyFeeds.model.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ResourceNotFoundException;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.paginators.ScanIterable;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.services.s3.paginators.ListObjectsV2Iterable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AWSService {

    @Autowired
    private AWSConfiguration awsConfig;
    @Value("${application.appClientID}")
    private String appClientId;
    @Value("${application.appClientSecret}")
    private String appClientSecret;


    @Value("${application.bucket.name}")
    private String bucketName;

    @Getter
    @Setter
    private String idToken;
    @Getter
    @Setter
    private String accessToken;
    @Getter
    @Setter
    private String refreshToken;

    public List<String> getAllUserPhotos(String userEmail) {
        List<String> res = new ArrayList<>();

        S3Client awsS3Client = awsConfig.getAwsS3Client();

        ListObjectsV2Request request = ListObjectsV2Request.builder().bucket(bucketName).prefix(userEmail + "/images/").build();
        ListObjectsV2Iterable response = awsS3Client.listObjectsV2Paginator(request);

        response.stream()
                .flatMap(r -> r.contents().stream())
                .forEach(content -> {
                    if (content.key().length() > userEmail.length() + 8) {
                        GetObjectRequest objectRequest = GetObjectRequest
                                .builder()
                                .key(content.key())
                                .bucket(bucketName)
                                .build();

                        ResponseBytes<GetObjectResponse> objectBytes = awsS3Client.getObjectAsBytes(objectRequest);
                        byte[] data = Base64.getEncoder().encode(objectBytes.asByteArray());
                        res.add(new String(data));
                    }
                });

        return res;

    }

    public List<UserSearchModel> getSearchUserList(String userSearchName) {

        List<UserSearchModel> result = new ArrayList<>();

        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        ScanRequest request =
                ScanRequest
                        .builder()
                        .tableName("happy-feeds-user-data")
                        .filterExpression("begins_with(id,:id)")
                        .expressionAttributeValues(
                                Map.of(":id", AttributeValue.builder().s(userSearchName).build())
                        )
                        .projectionExpression("id, fullName")
                        .build();
        ScanIterable response = ddb.scanPaginator(request);

        for (ScanResponse page : response) {
            for (Map<String, AttributeValue> item : page.items()) {
                // Consume the item
                UserSearchModel userSearchModel = new UserSearchModel();
                userSearchModel.setEmail(item.get("id").s());
                userSearchModel.setFullName(item.get("fullName").s());
                result.add(userSearchModel);
            }
        }

        return result;
    }

    public String upload(String userEmail, MultipartFile file, String caption) {
        String res = "";

        S3Client awsS3Client = awsConfig.getAwsS3Client();
        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        try {
            int totalUploadedMemories = getListSizeOfUserMemories(userEmail) + 1;
            String imageName = "img" + String.valueOf(totalUploadedMemories) + "." + "jpg";
            PutObjectRequest objectRequest = PutObjectRequest.builder()
                    .bucket("happy-feeds")
                    .key(userEmail + "/images/" + imageName)
                    .build();

            awsS3Client.putObject(objectRequest, RequestBody.fromByteBuffer(ByteBuffer.wrap(file.getBytes())));
            //update caption in dynamoDB
            updateFeedOrCaption(userEmail, true, caption);

            List<String> friendsList = getFriends(userEmail, "Friends");
            String value = userEmail + "/images/" + imageName;
            for (String user : friendsList) {
                updateFeedOrCaption(user, false, value);
            }

            res = "File uploaded successfully";
        } catch (AwsServiceException ex) {
            System.out.println(ex.awsErrorDetails().errorMessage());
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        return res;
    }

    private int getListSizeOfUserMemories(String userEmail) {
        int res = 0;
        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        HashMap<String, AttributeValue> keyToGet = new HashMap<String, AttributeValue>();

        keyToGet.put("id", AttributeValue.builder()
                .s(userEmail).build());

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName("happy-feeds-user-data")
                .projectionExpression("memories")
                .build();

        try {
            Map<String, AttributeValue> returnedItem = ddb.getItem(request).item();

            List<AttributeValue> listOfImages = returnedItem.get("memories").l();
            res = listOfImages.size();

        } catch (DynamoDbException e) {
            System.out.println(e.getMessage());

        }

        return res;
    }

    private String getFriendStatus(String userEmail, String otherUserEmail) {
        String res = "";
        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        HashMap<String, AttributeValue> keyToGet = new HashMap<String, AttributeValue>();

        keyToGet.put("id", AttributeValue.builder()
                .s(userEmail).build());

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName("happy-feeds-user-data")
                .projectionExpression("friends")
                .build();

        try {
            Map<String, AttributeValue> returnedItem = ddb.getItem(request).item();

            Map<String, AttributeValue> friendsList = returnedItem.get("friends").m();

            if (friendsList.containsKey((otherUserEmail))) {
                res = friendsList.get(otherUserEmail).s();
            }

        } catch (DynamoDbException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        return res;
    }

    private void updateFeedOrCaption(String userEmail, boolean caption, String value) {

        String updateExpression = caption ? "SET memories=list_append(memories, :attrValue)" : "SET feeds=list_append(feeds, :attrValue)";

        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        HashMap<String, AttributeValue> itemKey = new HashMap<String, AttributeValue>();

        itemKey.put("id", AttributeValue.builder().s(userEmail).build());

        HashMap<String, AttributeValue> updatedValues =
                new HashMap<String, AttributeValue>();

        // Update the column specified by name with updatedVal
        updatedValues.put(":attrValue", AttributeValue.builder().l(AttributeValue.fromS(value)).build());

        UpdateItemRequest request = UpdateItemRequest.builder()
                .tableName("happy-feeds-user-data")
                .key(itemKey)
                .updateExpression(updateExpression)
                .expressionAttributeValues(updatedValues)
                .build();

        try {
            ddb.updateItem(request);
        } catch (ResourceNotFoundException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        } catch (DynamoDbException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    public UserLoginResponseModel loginUser(UserLoginRequestModel loginDetails) {

        CognitoIdentityProviderClient cognitoClient = awsConfig.getCognitoClient();

        String email = loginDetails.getEmail();
        String password = loginDetails.getPassword();
        String generatedSecretHash = calculateSecretHash(appClientId, appClientSecret, email);

        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", email);
        authParams.put("PASSWORD", password);
        authParams.put("SECRET_HASH", generatedSecretHash);

        InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest.builder()
                .clientId(appClientId)
                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .authParameters(authParams)
                .build();

        InitiateAuthResponse initiateAuthResponse = cognitoClient.initiateAuth(initiateAuthRequest);
        AuthenticationResultType authenticationResultType = initiateAuthResponse.authenticationResult();

        UserLoginResponseModel userLoginResult = new UserLoginResponseModel();
        userLoginResult.setSuccessful(initiateAuthResponse.sdkHttpResponse().isSuccessful());
        userLoginResult.setStatusCode(initiateAuthResponse.sdkHttpResponse().statusCode());

        String token = authenticationResultType.idToken();
        String[] parts = token.split("\\.");
        JsonObject payload = JsonParser.parseString(decode(parts[1])).getAsJsonObject();

        String user_email = payload.get("email").getAsString();
        String user_name = payload.get("name").getAsString();

        setIdToken(authenticationResultType.idToken());
        setAccessToken(authenticationResultType.accessToken());
        setRefreshToken(authenticationResultType.refreshToken());

        userLoginResult.setEmail(user_email);
        userLoginResult.setName(user_name);

        return userLoginResult;
    }

    public UserSignUpResponseModel createUser(UserSignUpRequestModel userDetails) {

        CognitoIdentityProviderClient cognitoClient = awsConfig.getCognitoClient();

        String email = userDetails.getEmail();
        String password = userDetails.getPassword();
        String firstName = userDetails.getFirstName();
        String lastName = userDetails.getLastName();

        String generatedSecretHash = calculateSecretHash(appClientId, appClientSecret, email);

        AttributeType emailAttribute = AttributeType.builder()
                .name("email")
                .value(email)
                .build();

        AttributeType nameAttribute = AttributeType.builder()
                .name("name")
                .value(firstName + " " + lastName)
                .build();

        List<AttributeType> attributes = new ArrayList<>();
        attributes.add(emailAttribute);
        attributes.add(nameAttribute);

        SignUpRequest signUpRequest = SignUpRequest.builder()
                .username(email)
                .password(password)
                .userAttributes(attributes)
                .clientId(appClientId)
                .secretHash(generatedSecretHash)
                .build();

        SignUpResponse signUpResponse = cognitoClient.signUp(signUpRequest);

        UserSignUpResponseModel userSignUpResponse = new UserSignUpResponseModel();
        userSignUpResponse.setSuccessful(signUpResponse.sdkHttpResponse().isSuccessful());
        userSignUpResponse.setStatusCode(signUpResponse.sdkHttpResponse().statusCode());
        userSignUpResponse.setCognitoUserID(signUpResponse.userSub());
        userSignUpResponse.setConfirmed(signUpResponse.userConfirmed());

        return userSignUpResponse;
    }

    public OtherUserProfile otherUserDetails(String otherUserEmail, String currentUserEmail) {

        OtherUserProfile otherUserDetailsResponse = new OtherUserProfile();

        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        if (getDP(otherUserEmail).length != 0)
            otherUserDetailsResponse.setUserDP(getDP(otherUserEmail));

        ScanRequest request =
                ScanRequest
                        .builder()
                        .tableName("happy-feeds-user-data")
                        .filterExpression("id = :id")
                        .expressionAttributeValues(
                                Map.of(":id", AttributeValue.builder().s(otherUserEmail).build())
                        )
                        .projectionExpression("id, fullName, friends, memories")
                        .build();
        ScanIterable response = ddb.scanPaginator(request);

        for (ScanResponse page : response) {
            for (Map<String, AttributeValue> item : page.items()) {
                // Consume the item
                otherUserDetailsResponse.setEmail(item.get("id").s());
                otherUserDetailsResponse.setName(item.get("fullName").s());
                //otherUserDetailsResponse.setFriendsCount(item.get("friends").m().size());
                otherUserDetailsResponse.setFriendStatus("Send Request");

                Map<String, AttributeValue> friendsList = item.get("friends").m();

                Map<String, String> filteredMap = friendsList.entrySet()
                        .stream().filter(x -> "Friends".equals(x.getValue().s()))
                        .collect(Collectors.toMap(x -> x.getKey(), y -> y.getValue().s()));

                otherUserDetailsResponse.setFriendsCount(filteredMap.size());

                if (friendsList.containsKey(currentUserEmail)) {
                    otherUserDetailsResponse.setFriendStatus(friendsList.get(currentUserEmail).s());
                }


                List<String> otherUserPhotos = new ArrayList<>();
                otherUserDetailsResponse.setUserPhotos(otherUserPhotos);
                int photosSize = item.get("memories").l().size();

                if (otherUserDetailsResponse.getFriendStatus().equals("Friends") && photosSize > 0) {
                    otherUserPhotos = getAllUserPhotos(otherUserEmail);
                    otherUserDetailsResponse.setUserPhotos(otherUserPhotos);
                }
            }
        }

        return otherUserDetailsResponse;
    }

    public String sendRequest(String otherUserEmail, String currentUserEmail) {
        String res = "";
        try {
            updateTableForFriendRequest(currentUserEmail, otherUserEmail, true);
            updateTableForFriendRequest(otherUserEmail, currentUserEmail, false);
            res = "Done";
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return res;
    }

    public String acceptRequest(String otherUserEmail, String currentUserEmail) {
        String res = "";
        try {
            updateTableForAcceptRequest(currentUserEmail, otherUserEmail);
            updateTableForAcceptRequest(otherUserEmail, currentUserEmail);
            res = "Done";
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return res;
    }

    private void updateTableForFriendRequest(String currentUserEmail, String otherUserEmail, boolean sentByCurrentUser) {
        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        String status = sentByCurrentUser ? "Accept Request" : "Request Sent";

        HashMap<String, AttributeValue> itemKey = new HashMap<String, AttributeValue>();
        itemKey.put("id", AttributeValue.builder().s(currentUserEmail).build());

        HashMap<String, AttributeValue> updatedValues1 =
                new HashMap<String, AttributeValue>();

        HashMap<String, String> updatedValues2 =
                new HashMap<String, String>();

        updatedValues1.put(":attrValue", AttributeValue.builder().s(status).build());
        updatedValues2.put("#attrKey", otherUserEmail);

        UpdateItemRequest request1 = UpdateItemRequest.builder()
                .tableName("happy-feeds-user-data")
                .key(itemKey)
                .updateExpression("SET friends.#attrKey = :attrValue")
                .expressionAttributeNames(updatedValues2)
                .expressionAttributeValues(updatedValues1)
                .build();

        HashMap<String, AttributeValue> updatedValues3 =
                new HashMap<String, AttributeValue>();

        Map<String, AttributeValue> updateMap2 = new HashMap<>();
        if (sentByCurrentUser) {
            updateMap2.put("sentTo", AttributeValue.fromS(otherUserEmail));
            updateMap2.put("sentBy", AttributeValue.fromS(currentUserEmail));
        } else {
            updateMap2.put("sentTo", AttributeValue.fromS(currentUserEmail));
            updateMap2.put("sentBy", AttributeValue.fromS(otherUserEmail));
        }
        updateMap2.put("showBadge", AttributeValue.fromBool(true));
        updatedValues3.put(":attrValue", AttributeValue.builder().l(AttributeValue.fromM(updateMap2)).build());

        UpdateItemRequest request2 = UpdateItemRequest.builder()
                .tableName("happy-feeds-user-data")
                .key(itemKey)
                .updateExpression("SET friend_request = list_append(friend_request, :attrValue)")
                .expressionAttributeValues(updatedValues3)
                .build();

        try {
            ddb.updateItem(request1);
            ddb.updateItem(request2);
        } catch (ResourceNotFoundException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        } catch (DynamoDbException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    private void updateTableForAcceptRequest(String currentUserEmail, String otherUserEmail) {
        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        //String status = sentByCurrentUser?"Request Sent":"Accept Request";

        HashMap<String, AttributeValue> itemKey = new HashMap<String, AttributeValue>();
        itemKey.put("id", AttributeValue.builder().s(currentUserEmail).build());

        HashMap<String, AttributeValue> updatedValues1 =
                new HashMap<String, AttributeValue>();
        HashMap<String, String> updatedValues2 =
                new HashMap<String, String>();


        updatedValues1.put(":attrValue", AttributeValue.builder().s("Friends").build());
        updatedValues2.put("#attrKey", otherUserEmail);

        UpdateItemRequest request1 = UpdateItemRequest.builder()
                .tableName("happy-feeds-user-data")
                .key(itemKey)
                .updateExpression("SET friends.#attrKey = :attrValue")
                .expressionAttributeNames(updatedValues2)
                .expressionAttributeValues(updatedValues1)
                .build();

        try {
            ddb.updateItem(request1);
        } catch (ResourceNotFoundException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        } catch (DynamoDbException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    public List<String> getFriends(String userEmail, String status) {
        List<String> result = new ArrayList<>();
        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        HashMap<String, AttributeValue> keyToGet = new HashMap<String, AttributeValue>();

        keyToGet.put("id", AttributeValue.builder()
                .s(userEmail).build());

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName("happy-feeds-user-data")
                .projectionExpression("friends, friend_request")
                .build();

        try {
            Map<String, AttributeValue> returnedItem = ddb.getItem(request).item();

            List<AttributeValue> friendRequests = returnedItem.get("friend_request").l();
            Map<String, AttributeValue> friendsList = returnedItem.get("friends").m();

            result = friendRequests.stream().filter(val -> status.equals(
                    friendsList.get(val.m().get("sentBy").s().equals(userEmail) ? val.m().get("sentTo").s() : val.m().get("sentBy").s()).s()
            )).map(val -> val.m().get("sentBy").s().equals(userEmail) ? val.m().get("sentTo").s() : val.m().get("sentBy").s()).collect(Collectors.toList());


        } catch (DynamoDbException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }

        return result;
    }

    public String uploadDP(String userEmail, String file) {
        String res = "";

        S3Client awsS3Client = awsConfig.getAwsS3Client();
        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        try {
            String imageName = "dp.jpg";
            PutObjectRequest objectRequest = PutObjectRequest.builder()
                    .bucket("happy-feeds")
                    .key(userEmail + "/" + imageName)
                    .build();

            byte[] imageByte = Base64.getDecoder().decode(file);

            awsS3Client.putObject(objectRequest, RequestBody.fromByteBuffer(ByteBuffer.wrap(imageByte)));
            //update dp in dynamoDB
            HashMap<String, AttributeValue> itemKey = new HashMap<String, AttributeValue>();

            itemKey.put("id", AttributeValue.builder().s(userEmail).build());

            HashMap<String, AttributeValue> updatedValues =
                    new HashMap<String, AttributeValue>();

            // Update the column specified by name with updatedVal
            updatedValues.put(":attrValue", AttributeValue.builder().bool(true).build());

            UpdateItemRequest request = UpdateItemRequest.builder()
                    .tableName("happy-feeds-user-data")
                    .key(itemKey)
                    .updateExpression("SET dp = :attrValue")
                    .expressionAttributeValues(updatedValues)
                    .build();

            ddb.updateItem(request);

            res = "File uploaded successfully";
        } catch (AwsServiceException ex) {
            System.out.println(ex.awsErrorDetails().errorMessage());
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        return res;
    }

    public UserProfile getUserProfile(String userEmail) {
        UserProfile profile = new UserProfile();

        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        HashMap<String, AttributeValue> keyToGet = new HashMap<String, AttributeValue>();

        keyToGet.put("id", AttributeValue.builder()
                .s(userEmail).build());

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName("happy-feeds-user-data")
                .projectionExpression("id, fullName, dp")
                .build();

        try {
            Map<String, AttributeValue> returnedItem = ddb.getItem(request).item();

            if (returnedItem != null) {
                profile.setEmail(returnedItem.get("id").s());
                profile.setName(returnedItem.get("fullName").s());
                profile.setDp("");
            }

            if (returnedItem.get("dp").bool()) {
                String dpURL = Base64.getEncoder().encodeToString(getDP(userEmail));
                profile.setDp(dpURL);
            }

        } catch (DynamoDbException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }

        return profile;
    }

    private byte[] getDP(String userEmail) {

        byte[] data = new byte[]{};

        DynamoDbClient ddb = awsConfig.getDynamoDBClient();

        HashMap<String, AttributeValue> keyToGet = new HashMap<String, AttributeValue>();

        keyToGet.put("id", AttributeValue.builder()
                .s(userEmail).build());

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName("happy-feeds-user-data")
                .projectionExpression("id, fullName, dp")
                .build();

        Map<String, AttributeValue> returnedItem = ddb.getItem(request).item();

        if (returnedItem.get("dp").bool()) {
            S3Client awsS3Client = awsConfig.getAwsS3Client();

            GetObjectRequest objectRequest = GetObjectRequest
                    .builder()
                    .key(userEmail + "/" + "dp.jpg")
                    .bucket(bucketName)
                    .build();

            ResponseBytes<GetObjectResponse> objectBytes = awsS3Client.getObjectAsBytes(objectRequest);
            data = objectBytes.asByteArray();
        }

        return data;
    }

    public UserHome getUserHome(String userEmail) {
        UserHome userHome = new UserHome();

        DynamoDbClient ddb = awsConfig.getDynamoDBClient();
        HashMap<String, AttributeValue> keyToGet = new HashMap<String, AttributeValue>();
        keyToGet.put("id", AttributeValue.builder()
                .s(userEmail).build());

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName("happy-feeds-user-data")
                .projectionExpression("feeds, memories")
                .build();
        Map<String, AttributeValue> returnedItem = ddb.getItem(request).item();

        List<AttributeValue> feeds = returnedItem.get("feeds").l();

        List<UserFeeds> userFeeds = new ArrayList<>();
        for (AttributeValue userFeed : feeds) {
            String[] details = userFeed.s().split("/");
            List<String> feedInfo = getFeedInfo(details[0], details[2]);
            UserFeeds feedDetails = new UserFeeds();
            feedDetails.setEmail(feedInfo.get(0));
            feedDetails.setName(feedInfo.get(1));
            feedDetails.setCaption(feedInfo.get(2));
            feedDetails.setImage(feedInfo.get(3));

            userFeeds.add(feedDetails);
        }

        userHome.setFeeds(feeds.size());
        userHome.setPosts(getListSizeOfUserMemories(userEmail));
        userHome.setUserFeedsList(userFeeds);

        return userHome;
    }

    private List<String> getFeedInfo(String userEmail, String imgName) {

        List<String> res = new ArrayList<>();
        //email
        res.add(userEmail);

        DynamoDbClient ddb = awsConfig.getDynamoDBClient();
        HashMap<String, AttributeValue> keyToGet = new HashMap<String, AttributeValue>();
        keyToGet.put("id", AttributeValue.builder()
                .s(userEmail).build());

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName("happy-feeds-user-data")
                .projectionExpression("memories, fullName")
                .build();

        Map<String, AttributeValue> returnedItem = ddb.getItem(request).item();
        //name
        res.add(returnedItem.get("fullName").s());

        List<AttributeValue> memories = returnedItem.get("memories").l();
        String[] imgDetails = imgName.split(".");
        int captionInd = Integer.parseInt(imgName.substring(3, imgName.indexOf(".")));

        String cap = memories.get(captionInd - 1).s();

        //caption
        res.add(cap);


        S3Client awsS3Client = awsConfig.getAwsS3Client();
        GetObjectRequest objectRequest = GetObjectRequest
                .builder()
                .key(userEmail + "/images/" + imgName)
                .bucket(bucketName)
                .build();

        ResponseBytes<GetObjectResponse> objectBytes = awsS3Client.getObjectAsBytes(objectRequest);
        byte[] data = Base64.getEncoder().encode(objectBytes.asByteArray());

        //img
        res.add(new String(data));

        return res;
    }

    public HttpHeaders headers() {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set("IdToken", getIdToken());
        responseHeaders.set("AccessToken", getAccessToken());
        responseHeaders.set("RefreshToken", getRefreshToken());

        return responseHeaders;
    }

    public boolean verifyJWT(String IdToken) {
        String aws_cognito_region = "us-east-1"; // Replace this with your aws cognito region
        String aws_user_pools_id = "us-east-1_sxTfYmV6C"; // Replace this with your aws user pools id

        boolean res = false;

        try {
            RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(aws_cognito_region, aws_user_pools_id);
            Algorithm algorithm = Algorithm.RSA256(keyProvider);
            JWTVerifier jwtVerifier = JWT.require(algorithm)
                    //.withAudience("2qm9sgg2kh21masuas88vjc9se") // Validate your apps audience if needed
                    .build();

            jwtVerifier.verify(IdToken);

            res = true;
        } catch (Exception ex) {
        }

        return res;

    }

    public static String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName) {
        final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

        SecretKeySpec signingKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
                HMAC_SHA256_ALGORITHM);
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            mac.update(userName.getBytes(StandardCharsets.UTF_8));
            byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating ");
        }
    }

    private static String decode(String encodedString) {
        return new String(Base64.getUrlDecoder().decode(encodedString));
    }

}

