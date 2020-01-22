/*
 * Name:           Burp Indicators of Vulnerability
 * Version:        0.1.0
 * Date:           1/17/2019
 * Author:         Josh Berry - josh.berry@codewatch.org
 * Github:         https://github.com/codewatchorg/Burp-AnonymousCloud
 * 
 * Description:    This plugin checks application responses and in some cases browser requests for indications of SQLi, XXE, and other vulnerabilities or attack points for these issues.
 * 
 * Contains regex work from Cloud Storage Tester by VirtueSecurity: https://github.com/VirtueSecurity/aws-extender
 *
*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.Random;
import java.io.PrintWriter;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.awt.Component;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.HeadBucketRequest;
import com.amazonaws.services.s3.model.AccessControlList;
import com.amazonaws.services.s3.model.GroupGrantee;
import com.amazonaws.services.s3.model.Permission;
import com.amazonaws.regions.Regions;
import java.util.Iterator;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab {

  // Setup extension wide variables
  public IBurpExtenderCallbacks extCallbacks;
  public IExtensionHelpers extHelpers;
  private static final String burpAnonCloudVersion = "0.1.0";
  private static final Pattern S3BucketPattern = Pattern.compile("((?:\\w+://)?(?:([\\w.-]+)\\.s3[\\w.-]*\\.amazonaws\\.com|s3(?:[\\w.-]*\\.amazonaws\\.com(?:(?::\\d+)?\\\\?/)*|://)([\\w.-]+))(?:(?::\\d+)?\\\\?/)?(?:.*?\\?.*Expires=(\\d+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern GoogleBucketPattern = Pattern.compile("((?:\\w+://)?(?:([\\w.-]+)\\.storage[\\w-]*\\.googleapis\\.com|(?:(?:console\\.cloud\\.google\\.com/storage/browser/|storage[\\w-]*\\.googleapis\\.com)(?:(?::\\d+)?\\\\?/)*|gs://)([\\w.-]+))(?:(?::\\d+)?\\\\?/([^\\s?#]*))?(?:.*\\?.*Expires=(\\d+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureBucketPattern = Pattern.compile("(([\\w.-]+\\.blob\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AwsRegionPattern = Pattern.compile("x-amz-bucket-region:");
  public JPanel anonCloudPanel;
  private String awsAccessKey = "";
  private String awsSecretAccessKey = "";
  private String BucketName = "";
  private Boolean isAuthSet = false;
  AWSCredentials anonCredentials = new AnonymousAWSCredentials();
  AWSCredentials authCredentials;
  AmazonS3 anonS3client = AmazonS3ClientBuilder
    .standard()
    .withForceGlobalBucketAccessEnabled(true)
    .withRegion(Regions.DEFAULT_REGION)
    .withCredentials(new AWSStaticCredentialsProvider(anonCredentials))
    .build();
  AmazonS3 authS3client;
  private PrintWriter printOut;

  // Basic extension setup
  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    extCallbacks = callbacks;
    extHelpers = extCallbacks.getHelpers();
    extCallbacks.setExtensionName("Anonymous Cloud");
    printOut = new PrintWriter(extCallbacks.getStdout(), true);
    extCallbacks.registerScannerCheck(this);
    
    // Create a tab to configure credential values
    anonCloudPanel = new JPanel(null);
    JLabel anonCloudAwsKeyLabel = new JLabel();
    JLabel anonCloudAwsKeyDescLabel = new JLabel();
    JLabel anonCloudAwsSecretKeyLabel = new JLabel();
    JLabel anonCloudAwsSecretKeyDescLabel = new JLabel();
    final JTextField anonCloudAwsKeyText = new JTextField();
    final JTextField anonCloudAwsSecretKeyText = new JTextField();
    JButton anonCloudSetHeaderBtn = new JButton("Set Configuration");
    JLabel anonCloudSetHeaderDescLabel = new JLabel();
    
    // Set values for labels, panels, locations, for AWS stuff
    // AWS Access Key GUI
    anonCloudAwsKeyLabel.setText("AWS Access Key:");
    anonCloudAwsKeyDescLabel.setText("Any AWS authenticate user test: AWS Access Key.");
    anonCloudAwsKeyLabel.setBounds(16, 15, 125, 20);
    anonCloudAwsKeyText.setBounds(146, 12, 310, 26);
    anonCloudAwsKeyDescLabel.setBounds(606, 15, 600, 20);
    
    // AWS Secret Access Key GUI
    anonCloudAwsSecretKeyLabel.setText("AWS Secret Access Key:");
    anonCloudAwsSecretKeyDescLabel.setText("Any AWS authenticate user test: AWS Secret Access Key.");
    anonCloudAwsSecretKeyLabel.setBounds(16, 50, 125, 20);
    anonCloudAwsSecretKeyText.setBounds(146, 47, 310, 26);
    anonCloudAwsSecretKeyDescLabel.setBounds(606, 50, 600, 20);
    
    // Create button for setting options
    anonCloudSetHeaderDescLabel.setText("Enable access configuration.");
    anonCloudSetHeaderDescLabel.setBounds(606, 85, 600, 20);
    anonCloudSetHeaderBtn.setBounds(146, 82, 310, 26);
    
    anonCloudSetHeaderBtn.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        awsAccessKey = anonCloudAwsKeyText.getText();
        awsSecretAccessKey = anonCloudAwsSecretKeyText.getText();
        
        // If valid AWS keys were entered, setup a client
        if (awsAccessKey.matches("^(AIza[0-9A-Za-z-_]{35}|A3T[A-Z0-9]|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AGPA[A-Z0-9]{16}|AIDA[A-Z0-9]{16}|AROA[A-Z0-9]{16}|AIPA[A-Z0-9]{16}|ANPA[A-Z0-9]{16}|ANVA[A-Z0-9]{16})") && awsSecretAccessKey.length() == 40) {

          // Setup an authenticated S3 client for buckets configured to allow all authenticated AWS users
          authCredentials = new BasicAWSCredentials(awsAccessKey, awsSecretAccessKey);
          authS3client = AmazonS3ClientBuilder
            .standard()
            .withForceGlobalBucketAccessEnabled(true)
            .withRegion(Regions.DEFAULT_REGION)
            .withCredentials(new AWSStaticCredentialsProvider(authCredentials))
            .build();
          
          isAuthSet = true;
        }
      }
    });
    
    // Add labels and fields to tab
    anonCloudPanel.add(anonCloudAwsKeyLabel);
    anonCloudPanel.add(anonCloudAwsKeyDescLabel);
    anonCloudPanel.add(anonCloudAwsKeyText);
    anonCloudPanel.add(anonCloudAwsSecretKeyLabel);
    anonCloudPanel.add(anonCloudAwsSecretKeyDescLabel);
    anonCloudPanel.add(anonCloudAwsSecretKeyText);
    anonCloudPanel.add(anonCloudSetHeaderBtn);
    anonCloudPanel.add(anonCloudSetHeaderDescLabel);
    
    // Print extension header
    printHeader();
    
    // Add the tab to Burp
    extCallbacks.customizeUiComponent(anonCloudPanel);
    extCallbacks.addSuiteTab(BurpExtender.this);
  }
  
  // Tab caption
  @Override
  public String getTabCaption() { return "Anonymous Cloud"; }

  // Java component to return to Burp
  @Override
  public Component getUiComponent() { return anonCloudPanel; }
  
  // Print to extension output tab
  public void printHeader() {
    printOut.println("Anonymous Cloud: " + burpAnonCloudVersion + "\n====================\nMonitor requests and responses for AWS S3 Buckets, Google Storage Buckets, and Azure Storage Containers. Checks for unauthenticated read/write access to buckets, in addition to bucket enumeration attempts.\n\n"
      + "josh.berry@codewatch.org\n\n");
  }
  
  // Perform a passive check for cloud buckets
  @Override
  public List<IScanIssue> doPassiveScan(IHttpRequestResponse messageInfo) {
    // Only process requests if the URL is in scope
    if (extCallbacks.isInScope(extHelpers.analyzeRequest(messageInfo).getUrl())) {
    
      // Setup default response body variables
      String respRaw = new String(messageInfo.getResponse());
      String respBody = respRaw.substring(extHelpers.analyzeResponse(messageInfo.getResponse()).getBodyOffset());
      List<IScanIssue> issues = new ArrayList<>(1);
      
      // Create patter matchers for each type
      Matcher S3BucketMatch = S3BucketPattern.matcher(respBody);
      Matcher GoogleBucketMatch = GoogleBucketPattern.matcher(respBody);
      Matcher AzureBucketMatch = AzureBucketPattern.matcher(respBody);
      
      // Create an issue noting an AWS S3 Bucket was identified in the response
      if (S3BucketMatch.find()) {
        List<int[]> S3BucketMatches = getMatches(messageInfo.getResponse(), S3BucketMatch.group(0).getBytes());
        issues.add(new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, S3BucketMatches) },
          "[Anonymous Cloud] AWS S3 Bucket Identified",
          "The response body contained the following bucket: " + S3BucketMatch.group(0),
          "Information",
          "Firm"
        ));
        
        getBucketName(S3BucketMatch.group(0));
        
        if (validateBucket("anonymous")) {
          // Check for public read bucket anonymous access
          try {
            publicReadCheck("AWS", messageInfo, S3BucketMatches);
          } catch (Exception ignore) {}
          
          // Check for public write bucket anonymous access
          try {
            publicWriteCheck("AWS", messageInfo, S3BucketMatches);
          } catch (Exception ignore) {}
        }
        
        if (validateBucket("anyuser")) {
          // Check for any authenticated AWS user read bucket access
          try {
            anyAuthReadCheck("AWS", messageInfo, S3BucketMatches);
          } catch (Exception ignore) {}
          
          // Check for any authenticated AWS user write bucket access
          try {
            anyAuthWriteCheck("AWS", messageInfo, S3BucketMatches);
          } catch (Exception ignore) {}
        }
        
        // Create the base issue
        return issues;
      }
        
      // Create an issue noting a Google Bucket was identified in the response
      if (GoogleBucketMatch.find()) {
        List<int[]> GoogleBucketMatches = getMatches(messageInfo.getResponse(), GoogleBucketMatch.group(0).getBytes());
        issues.add(new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, GoogleBucketMatches) },
          "[Anonymous Cloud] Google Storage Bucket Identified",
          "The response body contained the following bucket: " + GoogleBucketMatch.group(0),
          "Information",
          "Firm"
        ));
        
        // Check for public read/write anonymous access
        try {
          publicReadCheck("Google", messageInfo, GoogleBucketMatches);
        } catch (Exception ignore) {}
        
        // Create the base issue
        return issues;
      }

      // Create an issue noting an Azure Bucket was identified in the response
      if (AzureBucketMatch.find()) {
        List<int[]> AzureBucketMatches = getMatches(messageInfo.getResponse(), AzureBucketMatch.group(0).getBytes());
        issues.add(new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, AzureBucketMatches) },
          "[Anonymous Cloud] Azure Storage Container Identified",
          "The response body contained the following bucket: " + AzureBucketMatch.group(0),
          "Information",
          "Firm"
        ));
        
        // Check for public read/write anonymous access
        try {
          publicReadCheck("Azure", messageInfo, AzureBucketMatches);
        } catch (Exception ignore) {}
        
        // Create the base issue
        return issues;
      }
    }
    
    return null;
  }

  // No active scanning for this but still must define it
  @Override
  public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
    return null;
  }
  
  // Grab bucket name from matched bucket URL
  public void getBucketName(String BucketUrl) {
      String BucketName = "";

      // Get the actual bucket name either in the form of bucketname.s3.amazonaws.com or s3.amazonaws.com/bucketname
      if (BucketUrl.startsWith("http://s3.amazonaws") || BucketUrl.startsWith("https://s3.amazonaws")) {
        String[] Bucket = BucketUrl.split("/");
        int BucketLen = Bucket.length;
        BucketName = BucketUrl.split("/")[BucketLen-1];
      } else {
        String[] Bucket = BucketUrl.split("/");
        int BucketLen = Bucket.length;
        BucketName = BucketUrl.split("/")[BucketLen-1];
        BucketName = BucketName.replaceAll("\\.s3.*\\.amazonaws\\.com", "");
      }
    this.BucketName = BucketName;
  }
  
  // Validate a bucket exists
  public Boolean validateBucket(String authType) {
      
    // Call s3client to validate bucket
    if (authType.equals("anonymous")) {
      if (this.anonS3client.doesBucketExistV2(BucketName)) {
        return true;
      } else {
        return false;
      }
    } else if (authType.equals("anyuser") && isAuthSet) {
      if (this.authS3client.doesBucketExistV2(BucketName)) {
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }
  
  // Generate random strings for write test
  public String genRandStr() {
    int leftLimit = 48; // numeral '0'
    int rightLimit = 122; // letter 'z'
    int targetStringLength = 12;
    Random random = new Random();
 
    String generatedString = random.ints(leftLimit, rightLimit + 1)
      .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
      .limit(targetStringLength)
      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
      .toString();
 
    return generatedString;
  }
  
  // Perform anonymous public read access check
  private void publicReadCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches) {
    
    // AWS specific checks
    if (BucketType.equals("AWS")) {

      // Obtain the buckets region and then create a client based on this region
      String strRegion = anonS3client.headBucket(new HeadBucketRequest(BucketName)).getBucketRegion();
      AmazonS3 s3clientList = AmazonS3ClientBuilder
        .standard()
        .withRegion(strRegion)
        .withCredentials(new AWSStaticCredentialsProvider(anonCredentials))
        .build();
        
      try {
        // Get a list of bucket objects
        ObjectListing bucketObjsListing = s3clientList.listObjects(BucketName);
        List<String>bucketObjs = new ArrayList<>();
        
        // Look through the objects and add to our list
        do {
          for (S3ObjectSummary objItem : bucketObjsListing.getObjectSummaries()) {
            bucketObjs.add(objItem.getKey());
          }
        } while (bucketObjsListing.isTruncated());
        
        // Setup basic variables for enumerating and building string of objects
        int firstBucket = 0;
        int bucketCounter = 1;
        int totalBuckets = bucketObjs.size();
        String ObjList = "";
        
        // Loop through our list ot build a string of all objects
        for (Iterator<String> it = bucketObjs.iterator(); it.hasNext();) {
          String obj = it.next();

          if (firstBucket == 0 && totalBuckets >= 1) {
            ObjList = obj;
            firstBucket = 1;
          } else if (totalBuckets == 2 && firstBucket == 1) {
            ObjList = ObjList + " and " + obj;
          } else if (firstBucket == 1 && bucketCounter == totalBuckets) {
            ObjList = ObjList + ", and " + obj;
          } else {
            ObjList = ObjList + ", " + obj;
          }
          
          bucketCounter++;
        }
        
        // Create public read access issue with the list of objects included
        IScanIssue publicReadIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(),
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
          "[Anonymous Cloud] Publicly Accessible AWS S3 Bucket",
          "The following bucket contents were enumerated from " + BucketName + ": " + ObjList + ".",
          "Medium",
          "Certain"
        );

        // Add public read access issue
        extCallbacks.addScanIssue(publicReadIssue);
        
        // Attempt to read the bucket ACL
        AccessControlList readAcl = s3clientList.getBucketAcl(BucketName);
          
        // Create public read ACL issue with the full ACL included
        if (readAcl.toString().contains("AccessControlList")) {

          // Create public read access issue with the list of objects included
          IScanIssue publicReadAclIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(),
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
            "[Anonymous Cloud] Publicly Accessible AWS S3 Bucket ACL",
            "The following bucket ACL was enumerated from " + BucketName + ": " + readAcl.toString() + ".",
            "Medium",
            "Certain"
          );
            
          // Add public read ACL access issue
          extCallbacks.addScanIssue(publicReadAclIssue);
        }
      } catch (Exception ignore) {} 
    }
  }
  
  // Perform anonymous public write access check
  private void publicWriteCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches) {
    
    // AWS specific checks
    if (BucketType.equals("AWS")) {

      // Obtain the buckets region and then create a client based on this region
      String strRegion = anonS3client.headBucket(new HeadBucketRequest(BucketName)).getBucketRegion();
      AmazonS3 s3clientList = AmazonS3ClientBuilder
        .standard()
        .withRegion(strRegion)
        .withCredentials(new AWSStaticCredentialsProvider(anonCredentials))
        .build();
        
      // Attempt to write to the bucket
      try {
        // Create a random string as the key
        String bucketItem = "Burp-AnonymousCloud-" + genRandStr() + ".txt";

        // Attempt the bucket write
        s3clientList.putObject(BucketName, bucketItem, "Burp-AnonymousCloud Extension Public Write Test!");
          
        // Check the bucket item
        S3Object writeObj = s3clientList.getObject(BucketName, bucketItem);
        
        // Check size of bucket item
        if (writeObj.getObjectMetadata().getContentLength() >= 47) {
              
          // Create public write access issue with object written
          IScanIssue publicWriteIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(),
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
            "[Anonymous Cloud] Publicly Writeable AWS S3 Bucket",
            "The following bucket object was created in " + BucketName + ": " + bucketItem + ".",
            "High",
            "Certain"
          );
            
          // Add public write access issue
          extCallbacks.addScanIssue(publicWriteIssue);
          
          // Attempt to write an ACL to the previously created object
          try {
            // Get the uploaded objects ACL
            AccessControlList ObjAcl = s3clientList.getObjectAcl(BucketName, bucketItem);
                      
            // Clear the ACL
            ObjAcl.getGrantsAsList().clear();
          
            // Set the permissions
            ObjAcl.grantPermission(GroupGrantee.AuthenticatedUsers, Permission.FullControl);
            
            // Set the ACL on the object
            s3clientList.setObjectAcl(BucketName, bucketItem, ObjAcl);
            
            // Make sure ACL was assigned
            if (s3clientList.getObjectAcl(BucketName, bucketItem).toString().contains("/groups/global/AuthenticatedUsers")) {
              // Create any authenticated AWS user write ACL issue with ACL written
              IScanIssue publicWriteAclIssue = new CustomScanIssue(
                messageInfo.getHttpService(),
                extHelpers.analyzeRequest(messageInfo).getUrl(),
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
                "[Anonymous Cloud] Publicly Writeable AWS S3 ACL",
                "Full permission was given to the " + bucketItem + " in the " + BucketName + " bucket for any authenticated AWS user.",
                "High",
                "Certain"
              );
            
              // Add public write ACL access issue
              extCallbacks.addScanIssue(publicWriteAclIssue);
            }
          } catch (Exception ignore) {}
        }
          
      } catch (Exception ignore) {}
    }
  }
  
  // Perform check for allowing any authenticated user read access
  private void anyAuthReadCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches) {
    
    // AWS specific checks
    if (BucketType.equals("AWS")) {

      // Obtain the buckets region and then create a client based on this region
      String strRegion = authS3client.headBucket(new HeadBucketRequest(BucketName)).getBucketRegion();
      AmazonS3 s3clientList = AmazonS3ClientBuilder
        .standard()
        .withRegion(strRegion)
        .withCredentials(new AWSStaticCredentialsProvider(authCredentials))
        .build();
        
      // Get a list of bucket objects
      ObjectListing bucketObjsListing = s3clientList.listObjects(BucketName);
      List<String>bucketObjs = new ArrayList<>();
        
      // Look through the objects and add to our list
      do {
        for (S3ObjectSummary objItem : bucketObjsListing.getObjectSummaries()) {
          bucketObjs.add(objItem.getKey());
        }
      } while (bucketObjsListing.isTruncated());
        
      // Setup basic variables for enumerating and building string of objects
      int firstBucket = 0;
      int bucketCounter = 1;
      int totalBuckets = bucketObjs.size();
      String ObjList = "";
        
      // Loop through our list ot build a string of all objects
      for (Iterator<String> it = bucketObjs.iterator(); it.hasNext();) {
        String obj = it.next();

        if (firstBucket == 0 && totalBuckets >= 1) {
          ObjList = obj;
          firstBucket = 1;
        } else if (totalBuckets == 2 && firstBucket == 1) {
          ObjList = ObjList + " and " + obj;
        } else if (firstBucket == 1 && bucketCounter == totalBuckets) {
          ObjList = ObjList + ", and " + obj;
        } else {
          ObjList = ObjList + ", " + obj;
        }
          
        bucketCounter++;
      }
        
      // Create any authenticated AWS user read access issue with the list of objects included
      IScanIssue anyAuthReadIssue = new CustomScanIssue(
        messageInfo.getHttpService(),
        extHelpers.analyzeRequest(messageInfo).getUrl(),
        new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
        "[Anonymous Cloud] Any Authenticated AWS User Accessible AWS S3 Bucket",
        "The following bucket contents were enumerated from " + BucketName + ": " + ObjList + ".",
        "Medium",
       "Certain"
      );
        
      // Add any authenticated AWS user read access issue
      extCallbacks.addScanIssue(anyAuthReadIssue);
      
      // Attempt to read the bucket ACL
      AccessControlList readAcl = s3clientList.getBucketAcl(BucketName);
          
      // Create public read ACL issue with the full ACL included
      if (readAcl.toString().contains("AccessControlList")) {

        // Create public read access issue with the list of objects included
        IScanIssue anyAuthReadAclIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(),
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
          "[Anonymous Cloud] Any Authenticated AWS User Accessible AWS S3 Bucket ACL",
          "The following bucket ACL was enumerated from " + BucketName + ": " + readAcl.toString() + ".",
          "Medium",
          "Certain"
        );
            
        // Add public read ACL access issue
        extCallbacks.addScanIssue(anyAuthReadAclIssue);
      }
    }
  }

  // Perform check for allowing any authenticated user write access
  private void anyAuthWriteCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches) {
    
    // AWS specific checks
    if (BucketType.equals("AWS")) {

      // Obtain the buckets region and then create a client based on this region
      String strRegion = authS3client.headBucket(new HeadBucketRequest(BucketName)).getBucketRegion();
      AmazonS3 s3clientList = AmazonS3ClientBuilder
        .standard()
        .withRegion(strRegion)
        .withCredentials(new AWSStaticCredentialsProvider(authCredentials))
        .build();
      
      // Attempt to write to the bucket
      try {
        // Create a random string as the key
        String bucketItem = "Burp-AnonymousCloud-" + genRandStr() + ".txt";

        // Attempt the bucket write
        s3clientList.putObject(BucketName, bucketItem, "Burp-AnonymousCloud Extension Any Authenticated AWS User Write Test!");
          
        // Check the bucket item
        S3Object writeObj = s3clientList.getObject(BucketName, bucketItem);
          
        // Check size of bucket item
        if (writeObj.getObjectMetadata().getContentLength() >= 47) {
              
          // Create any authenticated AWS user write issue with object written
          IScanIssue anyAuthWriteIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(),
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
            "[Anonymous Cloud] Any Authenticated AWS User Writeable AWS S3 Bucket",
            "The following bucket object was created in " + BucketName + ": " + bucketItem + ".",
            "High",
            "Certain"
          );
            
          // Add public write access issue
          extCallbacks.addScanIssue(anyAuthWriteIssue);
          
          // Attempt to write an ACL to the previously created object
          try {
            // Get the uploaded objects ACL
            AccessControlList ObjAcl = s3clientList.getObjectAcl(BucketName, bucketItem);
                      
            // Clear the ACL
            ObjAcl.getGrantsAsList().clear();
          
            // Set the permissions
            ObjAcl.grantPermission(GroupGrantee.AuthenticatedUsers, Permission.FullControl);
            
            // Set the ACL on the object
            s3clientList.setObjectAcl(BucketName, bucketItem, ObjAcl);
            
            // Make sure ACL was assigned
            if (s3clientList.getObjectAcl(BucketName, bucketItem).toString().contains("/groups/global/AuthenticatedUsers")) {
              // Create any authenticated AWS user write ACL issue with ACL written
              IScanIssue anyAuthWriteAclIssue = new CustomScanIssue(
                messageInfo.getHttpService(),
                extHelpers.analyzeRequest(messageInfo).getUrl(),
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
                "[Anonymous Cloud] Any Authenticated AWS User Writeable AWS S3 ACL",
                "Full permission was given to the " + bucketItem + " in the " + BucketName + " bucket for any authenticated AWS user.",
                "High",
                "Certain"
              );
            
              // Add public write ACL access issue
              extCallbacks.addScanIssue(anyAuthWriteAclIssue);
            }
          } catch (Exception ignore) {}
        }
          
      } catch (Exception ignore) {}
    }
  }
  
  @Override
  public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
    // This method is called when multiple issues are reported for the same URL 
    // path by the same extension-provided check. The value we return from this 
    // method determines how/whether Burp consolidates the multiple issues
    // to prevent duplication
    //
    // Since the issue name is sufficient to identify our issues as different,
    // if both issues have the same name, only report the existing issue
    // otherwise report both issues
    if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
      return -1;
    else return 0;
  }
  
  // helper method to search a response for occurrences of a literal match string
  // and return a list of start/end offsets
  private List<int[]> getMatches(byte[] response, byte[] match) {
    List<int[]> matches = new ArrayList<>();

    int start = 0;
    while (start < response.length) {
      start = extHelpers.indexOf(response, match, true, start, response.length);
      if (start == -1)
        break;
      matches.add(new int[] { start, start + match.length });
      start += match.length;
    }
        
    return matches;
  }
}
  
class CustomScanIssue implements IScanIssue {
  private IHttpService httpService;
  private URL url;
  private IHttpRequestResponse[] httpMessages;
  private String name;
  private String detail;
  private String severity;
  private String confidence;

  public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity, String confidence) {
    this.httpService = httpService;
    this.url = url;
    this.httpMessages = httpMessages;
    this.name = name;
    this.detail = detail;
    this.severity = severity;
    this.confidence = confidence;
  }
    
  @Override
  public URL getUrl() {
    return url;
  }

  @Override
  public String getIssueName() {
    return name;
  }

  @Override
  public int getIssueType() {
    return 0;
  }

  @Override
  public String getSeverity() {
    return severity;
  }

  @Override
  public String getConfidence() {
    return confidence;
  }

  @Override
  public String getIssueBackground() {
    return null;
  }

  @Override
  public String getRemediationBackground() {
    return null;
  }

  @Override
  public String getIssueDetail() {
    return detail;
  }

  @Override
  public String getRemediationDetail() {
    return null;
  }

  @Override
  public IHttpRequestResponse[] getHttpMessages() {
    return httpMessages;
  }

  @Override
  public IHttpService getHttpService() {
    return httpService;
  }
}