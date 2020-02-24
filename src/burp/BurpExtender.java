/*
 * Name:           Burp Anonymous Cloud
 * Version:        0.1.6
 * Date:           1/21/2019
 * Author:         Josh Berry - josh.berry@codewatch.org
 * Github:         https://github.com/codewatchorg/Burp-AnonymousCloud
 * 
 * Description:    This plugin checks for insecure AWS/Azure/Google application configurations
 * 
 * Contains regex work from Cloud Storage Tester by VirtueSecurity: https://github.com/VirtueSecurity/aws-extender
 *
*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.Random;
import java.io.InputStreamReader;
import java.io.BufferedReader;
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
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.entity.StringEntity;
import java.util.Iterator;
import org.json.JSONObject;
import org.json.JSONArray;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import javax.xml.parsers.*;
import java.io.StringReader;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab {

  // Setup extension wide variables
  public IBurpExtenderCallbacks extCallbacks;
  public IExtensionHelpers extHelpers;
  private static final String burpAnonCloudVersion = "0.1.6";
  private static final Pattern S3BucketPattern = Pattern.compile("((?:\\w+://)?(?:([\\w.-]+)\\.s3[\\w.-]*\\.amazonaws\\.com|s3(?:[\\w.-]*\\.amazonaws\\.com(?:(?::\\d+)?\\\\?/)*|://)([\\w.-]+))(?:(?::\\d+)?\\\\?/)?(?:.*?\\?.*Expires=(\\d+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern GoogleBucketPattern = Pattern.compile("((?:\\w+://)?(?:([\\w.-]+)\\.storage[\\w-]*\\.googleapis\\.com|(?:(?:console\\.cloud\\.google\\.com/storage/browser/|storage\\.cloud\\.google\\.com|storage[\\w-]*\\.googleapis\\.com)(?:(?::\\d+)?\\\\?/)*|gs://)([\\w.-]+))(?:(?::\\d+)?\\\\?/([^\\s?'\"#]*))?(?:.*\\?.*Expires=(\\d+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern GcpFirebase = Pattern.compile("([\\w.-]+\\.firebaseio\\.com/)", Pattern.CASE_INSENSITIVE );
  private static final Pattern AzureBucketPattern = Pattern.compile("(([\\w.-]+\\.blob\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureTablePattern = Pattern.compile("(([\\w.-]+\\.table\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureQueuePattern = Pattern.compile("(([\\w.-]+\\.queue\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureFilePattern = Pattern.compile("(([\\w.-]+\\.file\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  public JPanel anonCloudPanel;
  private String awsAccessKey = "";
  private String awsSecretAccessKey = "";
  private String googleBearerToken = "";
  private static final String GoogleValidationUrl = "https://storage.googleapis.com/storage/v1/b/";
  private static final String GoogleBucketUploadUrl = "https://storage.googleapis.com/upload/storage/v1/b/";
  private Boolean isAwsAuthSet = false;
  private Boolean isGoogleAuthSet = false;
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
    JLabel anonCloudGoogleBearerLabel = new JLabel();
    JLabel anonCloudGoogleBearerDescLabel = new JLabel();
    final JTextField anonCloudAwsKeyText = new JTextField();
    final JTextField anonCloudAwsSecretKeyText = new JTextField();
    final JTextField anonCloudGoogleBearerText = new JTextField();
    JButton anonCloudSetHeaderBtn = new JButton("Set Configuration");
    JLabel anonCloudSetHeaderDescLabel = new JLabel();
    
    // Set values for labels, panels, locations, for AWS stuff
    // AWS Access Key GUI
    anonCloudAwsKeyLabel.setText("AWS Access Key:");
    anonCloudAwsKeyDescLabel.setText("Any AWS authenticated user test: AWS Access Key.");
    anonCloudAwsKeyLabel.setBounds(16, 15, 125, 20);
    anonCloudAwsKeyText.setBounds(146, 12, 310, 26);
    anonCloudAwsKeyDescLabel.setBounds(606, 15, 600, 20);
    
    // AWS Secret Access Key GUI
    anonCloudAwsSecretKeyLabel.setText("AWS Secret Access Key:");
    anonCloudAwsSecretKeyDescLabel.setText("Any AWS authenticated user test: AWS Secret Access Key.");
    anonCloudAwsSecretKeyLabel.setBounds(16, 50, 125, 20);
    anonCloudAwsSecretKeyText.setBounds(146, 47, 310, 26);
    anonCloudAwsSecretKeyDescLabel.setBounds(606, 50, 600, 20);
    
    // Set values for labels, panels, locations, for Google stuff
    // Google Bearer Token
    anonCloudGoogleBearerLabel.setText("Google Bearer Token:");
    anonCloudGoogleBearerDescLabel.setText("Any Google authenticated user test: Google Bearer Token (use 'gcloud auth print-access-token')");
    anonCloudGoogleBearerLabel.setBounds(16, 85, 125, 20);
    anonCloudGoogleBearerText.setBounds(146, 82, 310, 26);
    anonCloudGoogleBearerDescLabel.setBounds(606, 85, 600, 20);
    
    // Create button for setting options
    anonCloudSetHeaderDescLabel.setText("Enable access configuration.");
    anonCloudSetHeaderDescLabel.setBounds(606, 120, 600, 20);
    anonCloudSetHeaderBtn.setBounds(146, 120, 310, 26);
    
    anonCloudSetHeaderBtn.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        awsAccessKey = anonCloudAwsKeyText.getText();
        awsSecretAccessKey = anonCloudAwsSecretKeyText.getText();
        googleBearerToken = anonCloudGoogleBearerText.getText();
        
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
          
          isAwsAuthSet = true;
        }
        
        if (googleBearerToken.matches("^ya29\\.[0-9A-Za-z\\-_]+")) {
          isGoogleAuthSet = true;
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
    anonCloudPanel.add(anonCloudGoogleBearerLabel);
    anonCloudPanel.add(anonCloudGoogleBearerDescLabel);
    anonCloudPanel.add(anonCloudGoogleBearerText);
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
      
      // Create patter matchers for each type
      Matcher S3BucketMatch = S3BucketPattern.matcher(respBody);
      Matcher GoogleBucketMatch = GoogleBucketPattern.matcher(respBody);
      Matcher AzureBucketMatch = AzureBucketPattern.matcher(respBody);
      Matcher AzureTableMatch = AzureTablePattern.matcher(respBody);
      Matcher AzureQueueMatch = AzureQueuePattern.matcher(respBody);
      Matcher AzureFileMatch = AzureFilePattern.matcher(respBody);
      Matcher GcpFirebaseMatch = GcpFirebase.matcher(respBody);
      
      // Create an issue noting an AWS S3 Bucket was identified in the response
      if (S3BucketMatch.find()) {
        List<int[]> S3BucketMatches = getMatches(messageInfo.getResponse(), S3BucketMatch.group(0).getBytes());
        IScanIssue awsIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, S3BucketMatches) },
          "[Anonymous Cloud] AWS S3 Bucket Identified",
          "The response body contained the following bucket: " + S3BucketMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the S3 bucket identification issue
        extCallbacks.addScanIssue(awsIdIssue);
        
        // Get the actual name of the bucket
        String BucketName = getBucketName("AWS", S3BucketMatch.group(0));
        
        // Perform anonymous checks
        if (validateBucket("AWS", "anonymous", BucketName)) {
          
          // Create a finding noting that the bucket is valid
          IScanIssue awsConfirmIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(), 
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, S3BucketMatches) },
            "[Anonymous Cloud] AWS S3 Bucket Exists",
            "The following bucket was confirmed to be valid: " + BucketName,
            "Low",
            "Certain"
          );
          
          // Add confirmed bucket issue
          extCallbacks.addScanIssue(awsConfirmIssue);
          
          // Check for public read bucket anonymous access
          try {
            publicReadCheck("AWS", messageInfo, S3BucketMatches, BucketName);
          } catch (Exception ignore) {}
          
          // Check for public write bucket anonymous access
          try {
            publicWriteCheck("AWS", messageInfo, S3BucketMatches, BucketName);
          } catch (Exception ignore) {}
        }
        
        // Perform checks from the perspecitve of any authenticated AWS user
        if (validateBucket("AWS", "anyuser", BucketName)) {
          // Check for any authenticated AWS user read bucket access
          try {
            anyAuthReadCheck("AWS", messageInfo, S3BucketMatches, BucketName);
          } catch (Exception ignore) {}
          
          // Check for any authenticated AWS user write bucket access
          try {
            anyAuthWriteCheck("AWS", messageInfo, S3BucketMatches, BucketName);
          } catch (Exception ignore) {}
        }
      }
        
      // Create an issue noting a Google Bucket was identified in the response
      if (GoogleBucketMatch.find()) {
        List<int[]> GoogleBucketMatches = getMatches(messageInfo.getResponse(), GoogleBucketMatch.group(0).getBytes());
        IScanIssue googleIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, GoogleBucketMatches) },
          "[Anonymous Cloud] Google Storage Container Identified",
          "The response body contained the following bucket: " + GoogleBucketMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the Google bucket identification issue
        extCallbacks.addScanIssue(googleIdIssue);
        
        // Get the actual name of the bucket
        String BucketName = getBucketName("Google", GoogleBucketMatch.group(0));
        
        // Perform anonymous checks for Google
        if (validateBucket("Google", "anonymous", BucketName)) {
          
          // Create a finding noting that the bucket is valid
          IScanIssue googleConfirmIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(), 
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, GoogleBucketMatches) },
            "[Anonymous Cloud] Google Storage Container Exists",
            "The following bucket was confirmed to be valid: " + BucketName,
            "Low",
            "Certain"
          );
          
          // Add confirmed bucket issue
          extCallbacks.addScanIssue(googleConfirmIssue);
        
          // Check for public read anonymous access
          try {
            publicReadCheck("Google", messageInfo, GoogleBucketMatches, BucketName);
          } catch (Exception ignore) {}
          
          // Check for publc read ACL access
          try {
            publicReadAclCheck("Google", messageInfo, GoogleBucketMatches, BucketName);
          } catch (Exception ignore) {}
          
          // Check for publc write anonymous access
          try {
            publicWriteCheck("Google", messageInfo, GoogleBucketMatches, BucketName);
          } catch (Exception ignore) { }
        }
        
        // Perform checks from the perspecitve of any authenticated Google user
        if (validateBucket("Google", "anyuser", BucketName)) {
          // Check for any authenticated Google user read bucket access
          try {
            anyAuthReadCheck("Google", messageInfo, GoogleBucketMatches, BucketName);
          } catch (Exception ignore) {}
          
          // Check for any authenticated Google user read bucket ACL access
          try {
            anyAuthReadAclCheck("Google", messageInfo, GoogleBucketMatches, BucketName);
          } catch (Exception ignore) {}
          
          // Check for any authenticated Google user write bucket access
          try {
            anyAuthWriteCheck("Google", messageInfo, GoogleBucketMatches, BucketName);
          } catch (Exception ignore) {}
        }
      }
      
      // Create an issue noting an Azure Bucket was identified in the response
      if (AzureBucketMatch.find()) {
        List<int[]> AzureBucketMatches = getMatches(messageInfo.getResponse(), AzureBucketMatch.group(0).getBytes());
        IScanIssue azureIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, AzureBucketMatches) },
          "[Anonymous Cloud] Azure Storage Container Identified - Blob",
          "The response body contained the following bucket: " + AzureBucketMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the Azure bucket identification issue
        extCallbacks.addScanIssue(azureIdIssue);
        
        // Get the actual name of the bucket
        String BucketName = getBucketName("Azure", AzureBucketMatch.group(0));
        
        // Perform anonymous checks for Azure
        if (validateBucket("Azure", "anonymous", BucketName)) {
            
          IScanIssue azureAccountIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(), 
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, AzureBucketMatches) },
            "[Anonymous Cloud] Azure Storage Container Blob Account Identified",
            "The response confirmed the Azure Storage account exists: " + AzureBucketMatch.group(0),
            "Low",
            "Certain"
          );
            
          // Add the Azure bucket identification issue
          extCallbacks.addScanIssue(azureAccountIssue);
        
          // Check for public read/write anonymous access
          try {
            publicReadCheck("Azure", messageInfo, AzureBucketMatches, BucketName);
          } catch (Exception ignore) {}
        }
      }
      
      // Create an issue noting an Azure Table was identified in the response
      if (AzureTableMatch.find()) {
        List<int[]> AzureTableMatches = getMatches(messageInfo.getResponse(), AzureTableMatch.group(0).getBytes());
        IScanIssue azureTableIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, AzureTableMatches) },
          "[Anonymous Cloud] Azure Storage Container Identified - Table",
          "The response body contained the following table: " + AzureTableMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the Azure bucket identification issue
        extCallbacks.addScanIssue(azureTableIdIssue);
      }
      
      // Create an issue noting an Azure Queue was identified in the response
      if (AzureQueueMatch.find()) {
        List<int[]> AzureQueueMatches = getMatches(messageInfo.getResponse(), AzureQueueMatch.group(0).getBytes());
        IScanIssue azureQueueIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, AzureQueueMatches) },
          "[Anonymous Cloud] Azure Storage Container Identified - Queue",
          "The response body contained the following queue: " + AzureQueueMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the Azure bucket identification issue
        extCallbacks.addScanIssue(azureQueueIdIssue);
      }
      
      // Create an issue noting an Azure Share was identified in the response
      if (AzureFileMatch.find()) {
        List<int[]> AzureFileMatches = getMatches(messageInfo.getResponse(), AzureFileMatch.group(0).getBytes());
        IScanIssue azureFileIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, AzureFileMatches) },
          "[Anonymous Cloud] Azure Storage Container Identified - Share",
          "The response body contained the following share: " + AzureFileMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the Azure bucket identification issue
        extCallbacks.addScanIssue(azureFileIdIssue);
      }
      
      // Check for open Firebase access
      if (GcpFirebaseMatch.find()) {
        List<int[]> GcpFirebaseMatches = getMatches(messageInfo.getResponse(), GcpFirebaseMatch.group(0).getBytes());
        IScanIssue firebaseIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, GcpFirebaseMatches) },
          "[Anonymous Cloud] Firebase Database Identified",
          "The response body contained the following database: " + GcpFirebaseMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the Firebase identification issue
        extCallbacks.addScanIssue(firebaseIdIssue);
        
        // Check for public read/write anonymous access
        try {
          gcpFirebaseCheck(messageInfo, GcpFirebaseMatches, GcpFirebaseMatch.group(0));
        } catch (Exception ignore) {}
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
  public String getBucketName(String BucketType, String BucketUrl) {
    String BucketName = "";

    // Get buckets based on type
    if (BucketType.equals("AWS")) {
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
    } else if (BucketType.equals("Azure")) {
      BucketName = BucketUrl;
    } else if (BucketType.equals("Google")) {
      // Get the actual bucket name in the form of bucket.storage.googleapis.com, storage.googleapis.com/storage/v1/b/bucket, or console.cloud.google.com/storage/browser/bucket
      if (BucketUrl.startsWith("http://storage.googleapis.com") || BucketUrl.startsWith("https://storage.googleapis.com")) {
        String BucketPart = BucketUrl.replaceAll("(http|https)://storage.googleapis.com/storage/v1/b/", "");
        BucketName = BucketPart.split("/")[0];
      } else if (BucketUrl.startsWith("http://console.cloud.google.com") || BucketUrl.startsWith("https://console.cloud.google.com")) {
        String BucketPart = BucketUrl.replaceAll("(http|https)://console.cloud.google.com/storage/browser/", "");
        BucketName = BucketPart.split("/")[0];
      } else if (BucketUrl.startsWith("http://storage.cloud.google.com") || BucketUrl.startsWith("https://storage.cloud.google.com")) {
        String BucketPart = BucketUrl.replaceAll("(http|https)://storage.cloud.google.com/", "");
        BucketName = BucketPart.split("/")[0];
      } else {
        BucketName = BucketUrl.split("\\.")[0].replaceAll("(http|https)://", "");
      }
    }
    return BucketName;
  }
  
  // Validate a bucket exists
  public Boolean validateBucket(String bucketType, String authType, String BucketName) {
    
   // Get buckets based on type
    if (bucketType.equals("AWS")) { 
      // Call s3client to validate bucket
      if (authType.equals("anonymous")) {
        if (this.anonS3client.doesBucketExistV2(BucketName)) {
          return true;
        } else {
          return false;
        }
      } else if (authType.equals("anyuser") && isAwsAuthSet) {
        if (this.authS3client.doesBucketExistV2(BucketName)) {
          return true;
        } else {
          return false;
        }
      } else {
        return false;
      }
    } else if (bucketType.equals("Azure")) {
      // Create a client to check Azure for the storage account
        HttpClient client = HttpClientBuilder.create().build();
        HttpGet req = new HttpGet("https://" + BucketName + "?restype=container&comp=list");
        HttpResponse resp;
        Boolean bucketExists = false;
      
        // Connect to Azure services
        try {
          resp = client.execute(req);
          String headers = resp.getStatusLine().toString();
        
          // If we get a status then it exists
          if (headers.contains("200 OK") || headers.contains("401 Unauthorized") || headers.contains("404 The specified resource does not exist.")) {
            bucketExists = true;
          } else {
            bucketExists = false;
          }  
        } catch (Exception ignore) {}
        
        return bucketExists;
    } else if (bucketType.equals("Google")) {
      if (authType.equals("anonymous")) {
        // Create a client to check Google for the bucket
        HttpClient client = HttpClientBuilder.create().build();
        HttpGet req = new HttpGet(GoogleValidationUrl + BucketName);
        HttpResponse resp;
        Boolean bucketExists = false;
      
        // Connect to GCP services
        try {
          resp = client.execute(req);
          String headers = resp.getStatusLine().toString();
        
          // If the status is 200, it is public, of 401 then private, otherwise doesn't exist
          if (headers.contains("200 OK") || headers.contains("401 Unauthorized")) {
            bucketExists = true;
          } else {
            bucketExists = false;
          }
        } catch (Exception ignore) {}
      
        return bucketExists;
      } else if (authType.equals("anyuser") && isGoogleAuthSet) {
          
        // Create a client to check Google for the bucket
        HttpClient client = HttpClientBuilder.create().build();
        HttpGet req = new HttpGet(GoogleValidationUrl + BucketName);
        HttpResponse resp;
        Boolean bucketExists = false;
      
        // Connect to GCP services
        try {
          resp = client.execute(req);
          String headers = resp.getStatusLine().toString();
        
          // If the status is 200, it is public, of 401 then private, otherwise doesn't exist
          if (headers.contains("200 OK") || headers.contains("401 Unauthorized")) {
            bucketExists = true;
          } else {
            bucketExists = false;
          }
        } catch (Exception ignore) {}
      
        return bucketExists;
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
  private void publicReadCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches, String BucketName) {
    
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
        
        // Loop through our list to build a string of all objects
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
    
    // Google specific checks
    } else if (BucketType.equals("Google")) {
        
      // Create a client to check Google for the bucket
      HttpClient bucketClient = HttpClientBuilder.create().build();
      HttpGet reqBucket = new HttpGet(GoogleValidationUrl + BucketName + "/o");
      
      // Connect to GCP services for bucket access
      try {
        HttpResponse resp = bucketClient.execute(reqBucket);
        String headers = resp.getStatusLine().toString();

        // If the status is 200, it is public, of 401 then private, otherwise doesn't exist
        if (headers.contains("200 OK")) {
          
          // Read the response and get the JSON
          BufferedReader rd = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
          String jsonStr = "";
          String line = "";
          while ((line = rd.readLine()) != null) {
            jsonStr = jsonStr + line;
          }

          // Read JSON results from public bucket
          JSONObject json = new JSONObject(jsonStr);
          JSONArray bucketObjs = json.getJSONArray("items");
          
          // Setup basic variables for enumerating and building string of objects
          int firstBucket = 0;
          int bucketCounter = 1;
          int totalBuckets = bucketObjs.length();
          String ObjList = "";
        
          // Loop through our list to build a string of all objects
          for (int i = 0; i < bucketObjs.length(); i++) {
            String obj = bucketObjs.getJSONObject(i).getString("name");

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
            "[Anonymous Cloud] Publicly Accessible Google Storage Container",
            "The following bucket contents were enumerated from " + BucketName + ": " + ObjList + ".",
            "Medium",
            "Certain"
          );

          // Add public read access issue
          extCallbacks.addScanIssue(publicReadIssue);
        }
      } catch (Exception ignore) {}
    } else if (BucketType.equals("Azure")) {
        
      // Create a client to check Azure for the bucket
      HttpClient bucketClient = HttpClientBuilder.create().build();
      HttpGet reqBucket = new HttpGet("https://" + BucketName + "?restype=container&comp=list");
      
      // Connect to Azure services for bucket access
      try {
        HttpResponse resp = bucketClient.execute(reqBucket);
        String headers = resp.getStatusLine().toString();
        
        // If the status is 200, it is public, otherwise it isn't
        if (headers.contains("200 OK")) {
            
          // Read the response and get the XML
          BufferedReader rd = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
          String xmlStr = "";
          String line = "";
          int lineOne = 0;
          ArrayList<String> blobContents = new ArrayList<String>();
          
          // Put XML string together
          while ((line = rd.readLine()) != null) {
            if (lineOne == 0) {
              xmlStr = line.substring(3, line.length());
            } else {
              xmlStr = xmlStr + line; 
            }
          }
          
          // Read XML results from public bucket
          SAXParserFactory factory = SAXParserFactory.newInstance();
          SAXParser saxParser = factory.newSAXParser();
          
          // Create a handler for the XML
          DefaultHandler handler = new DefaultHandler() {
 
            // boolean to confirm name value
            boolean isName = false;
            
            // setup a handler for each element
            @Override
            public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {

              // if the element contains blobs, lookup details
              if (qName.equalsIgnoreCase("Name")) {
                isName = true;
              } else {
                isName = false;
              }
            }
            
            // setup hander for data in between tags
            @Override
            public void characters(char[] ch, int start, int length) {
              if (isName) {
                blobContents.add(new String(ch, start, length));
              }
            }
          };
 
          // process the XML data
          InputSource xmlSrc = new InputSource(new StringReader(xmlStr));
          saxParser.parse(xmlSrc, handler);
          
          // Setup basic variables for enumerating and building string of objects
          int firstBucket = 0;
          int bucketCounter = 1;
          int totalBuckets = blobContents.size();
          String ObjList = "";
        
          // Loop through our list to build a string of all objects
          for (int i = 0; i < blobContents.size(); i++) {
            String obj = blobContents.get(i);

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
            "[Anonymous Cloud] Publicly Accessible Azure Storage Container",
            "The following bucket contents were enumerated from " + BucketName + ": " + ObjList + ".",
            "Medium",
            "Certain"
          );

          // Add public read access issue
          extCallbacks.addScanIssue(publicReadIssue);
        }
      } catch (Exception ignore) { }
    }
  }
  
  // Perform anonymous public read ACL access check
  private void publicReadAclCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches, String BucketName) {
    
    // Google specific checks
    if (BucketType.equals("Google")) {
      
      // Create a client to check Google for the bucket
      HttpClient iamClient = HttpClientBuilder.create().build();
      HttpGet reqIam = new HttpGet(GoogleValidationUrl + BucketName + "/iam");
      
      // Connect to GCP services for bucket ACL access
      try {
        HttpResponse resp = iamClient.execute(reqIam);
        String headers = resp.getStatusLine().toString();

        // If the status is 200, it is public, of 401 then private, otherwise doesn't exist
        if (headers.contains("200 OK")) {
          
          // Read the response and get the JSON
          BufferedReader rd = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
          String jsonStr = "";
          String line = "";
          while ((line = rd.readLine()) != null) {
            jsonStr = jsonStr + line;
          }

          // Read JSON results from public bucket
          JSONObject json = new JSONObject(jsonStr);
          JSONArray bucketObjs = json.getJSONArray("bindings");
          
          // Setup basic variables for enumerating and building string of objects
          int firstBucket = 0;
          int bucketCounter = 1;
          int totalBuckets = bucketObjs.length();
          String ObjRoleList = "";
        
          // Loop through our list to build a string of all objects
          for (int i = 0; i < bucketObjs.length(); i++) {
            String objRole = bucketObjs.getJSONObject(i).getString("role");
            JSONArray memberObjs = bucketObjs.getJSONObject(i).getJSONArray("members");
            String objMembers = "";
            
            // Loop through ACL members
            for (int j = 0; j < memberObjs.length(); j++) {
              objMembers = objMembers + memberObjs.getString(j) + "; ";
            }

            if (firstBucket == 0 && totalBuckets >= 1) {
              ObjRoleList = "Role: " + objRole + " | Members: " + objMembers;
              firstBucket = 1;
            } else if (totalBuckets == 2 && firstBucket == 1) {
              ObjRoleList = ObjRoleList + " and Role: " + objRole + " | Members: " + objMembers;
            } else if (firstBucket == 1 && bucketCounter == totalBuckets) {
              ObjRoleList = ObjRoleList + ", and Role: " + objRole + " | Members: " + objMembers;
            } else {
              ObjRoleList = ObjRoleList + ", Role: " + objRole + " | Members: " + objMembers;
            }
          
            bucketCounter++;
          }
          
          // Create public read access issue with the list of objects included
          IScanIssue publicReadAclIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(),
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
            "[Anonymous Cloud] Publicly Accessible Google Storage Container ACL",
            "The following bucket contents were enumerated from " + BucketName + ": " + ObjRoleList + ".",
            "Medium",
            "Certain"
          );

          // Add public read access issue
          extCallbacks.addScanIssue(publicReadAclIssue);
        }
      } catch (Exception ignore) {}
    }
  }
  
  // Perform anonymous public write access check
  private void publicWriteCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches, String BucketName) {
    
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
            "[Anonymous Cloud] Publicly Writable AWS S3 Bucket",
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
                "[Anonymous Cloud] Publicly Writable AWS S3 ACL",
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
      
    // Google specific checks
    } else if (BucketType.equals("Google")) {
      
      // Create a client to check Google for the bucket
      String bucketItem = "Burp-AnonymousCloud-" + genRandStr() + ".txt";
      HttpClient client = HttpClientBuilder.create().build();
      HttpPost req = new HttpPost(GoogleBucketUploadUrl + BucketName + "/o?uploadType=media&name=" + bucketItem);
      String bucketContent = "Burp-AnonymousCloud Extension Public Write Test!";

      // Create and set headers for posting content
      Header headers[] = {
	new BasicHeader("Content-Type", "text/html")
      }; 
      req.setHeaders(headers);
      
      // Connect to GCP services for bucket ACL access
      try {
        req.setEntity(new StringEntity(bucketContent));
        HttpResponse resp = client.execute(req);
        String respHeaders = resp.getStatusLine().toString();

        // If the status is 200, it is public, of 401 then private, otherwise doesn't exist
        if (respHeaders.contains("200 OK")) {
          // Create public write access issue with object written
          IScanIssue publicWriteIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(),
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
            "[Anonymous Cloud] Publicly Writable Google Storage Container",
            "The following bucket object was created in " + BucketName + ": " + bucketItem + ".",
            "High",
            "Certain"
          );
          
          // Add public write bucket access issue
          extCallbacks.addScanIssue(publicWriteIssue);
        }
      } catch (Exception ignore) { }
    }
  }
  
  // Perform check for allowing any authenticated user read access
  private void anyAuthReadCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches, String BucketName) {
    
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
        
      // Loop through our list to build a string of all objects
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
    } else if (BucketType.equals("Google")) {
        
      // Create a client to check Google for the bucket
      HttpClient bucketClient = HttpClientBuilder.create().build();
      HttpGet reqBucket = new HttpGet(GoogleValidationUrl + BucketName + "/o");
      
      // Create and set headers for posting content
      Header headers[] = {
	new BasicHeader("Authorization", "Bearer " + googleBearerToken)
      }; 
      reqBucket.setHeaders(headers);
      
      // Connect to GCP services for bucket access
      try {
        HttpResponse resp = bucketClient.execute(reqBucket);
        String respHeaders = resp.getStatusLine().toString();

        // If the status is 200, it is public, of 401 then private, otherwise doesn't exist
        if (respHeaders.contains("200 OK")) {
          
          // Read the response and get the JSON
          BufferedReader rd = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
          String jsonStr = "";
          String line = "";
          while ((line = rd.readLine()) != null) {
            jsonStr = jsonStr + line;
          }

          // Read JSON results from public bucket
          JSONObject json = new JSONObject(jsonStr);
          JSONArray bucketObjs = json.getJSONArray("items");
          
          // Setup basic variables for enumerating and building string of objects
          int firstBucket = 0;
          int bucketCounter = 1;
          int totalBuckets = bucketObjs.length();
          String ObjList = "";
        
          // Loop through our list to build a string of all objects
          for (int i = 0; i < bucketObjs.length(); i++) {
            String obj = bucketObjs.getJSONObject(i).getString("name");

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
            "[Anonymous Cloud] Any Authenticated Google User Accessible Google Storage Container",
            "The following bucket contents were enumerated from " + BucketName + ": " + ObjList + ".",
            "Medium",
            "Certain"
          );

          // Add public read access issue
          extCallbacks.addScanIssue(publicReadIssue);
        }
      } catch (Exception ignore) {}
    }
  }
  
  // Perform anonymous public read ACL access check
  private void anyAuthReadAclCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches, String BucketName) {
    
    // Google specific checks
    if (BucketType.equals("Google")) {
      
      // Create a client to check Google for the bucket
      HttpClient iamClient = HttpClientBuilder.create().build();
      HttpGet reqIam = new HttpGet(GoogleValidationUrl + BucketName + "/iam");
      
      // Create and set headers for posting content
      Header headers[] = {
	new BasicHeader("Authorization", "Bearer " + googleBearerToken)
      }; 
      reqIam.setHeaders(headers);
      
      
      // Connect to GCP services for bucket ACL access
      try {
        HttpResponse resp = iamClient.execute(reqIam);
        String respHeaders = resp.getStatusLine().toString();

        // If the status is 200, it is public, of 401 then private, otherwise doesn't exist
        if (respHeaders.contains("200 OK")) {
          
          // Read the response and get the JSON
          BufferedReader rd = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
          String jsonStr = "";
          String line = "";
          while ((line = rd.readLine()) != null) {
            jsonStr = jsonStr + line;
          }

          // Read JSON results from public bucket
          JSONObject json = new JSONObject(jsonStr);
          JSONArray bucketObjs = json.getJSONArray("bindings");
          
          // Setup basic variables for enumerating and building string of objects
          int firstBucket = 0;
          int bucketCounter = 1;
          int totalBuckets = bucketObjs.length();
          String ObjRoleList = "";
        
          // Loop through our list to build a string of all objects
          for (int i = 0; i < bucketObjs.length(); i++) {
            String objRole = bucketObjs.getJSONObject(i).getString("role");
            JSONArray memberObjs = bucketObjs.getJSONObject(i).getJSONArray("members");
            String objMembers = "";
            
            // Loop through ACL members
            for (int j = 0; j < memberObjs.length(); j++) {
              objMembers = objMembers + memberObjs.getString(j) + "; ";
            }

            if (firstBucket == 0 && totalBuckets >= 1) {
              ObjRoleList = "Role: " + objRole + " | Members: " + objMembers;
              firstBucket = 1;
            } else if (totalBuckets == 2 && firstBucket == 1) {
              ObjRoleList = ObjRoleList + " and Role: " + objRole + " | Members: " + objMembers;
            } else if (firstBucket == 1 && bucketCounter == totalBuckets) {
              ObjRoleList = ObjRoleList + ", and Role: " + objRole + " | Members: " + objMembers;
            } else {
              ObjRoleList = ObjRoleList + ", Role: " + objRole + " | Members: " + objMembers;
            }
          
            bucketCounter++;
          }
          
          // Create public read access issue with the list of objects included
          IScanIssue publicReadAclIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(),
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
            "[Anonymous Cloud] Any Authenticated Google User Accessible Google Storage Container ACL",
            "The following bucket contents were enumerated from " + BucketName + ": " + ObjRoleList + ".",
            "Medium",
            "Certain"
          );

          // Add public read access issue
          extCallbacks.addScanIssue(publicReadAclIssue);
        }
      } catch (Exception ignore) {}
    }
  }

  // Perform check for allowing any authenticated user write access
  private void anyAuthWriteCheck(String BucketType, IHttpRequestResponse messageInfo, List<int[]>matches, String BucketName) {
    
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
            "[Anonymous Cloud] Any Authenticated AWS User Writable AWS S3 Bucket",
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
                "[Anonymous Cloud] Any Authenticated AWS User Writable AWS S3 ACL",
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
    } else if (BucketType.equals("Google")) {
      // Create a client to check Google for the bucket
      String bucketItem = "Burp-AnonymousCloud-" + genRandStr() + ".txt";
      HttpClient client = HttpClientBuilder.create().build();
      HttpPost req = new HttpPost(GoogleBucketUploadUrl + BucketName + "/o?uploadType=media&name=" + bucketItem);
      String bucketContent = "Burp-AnonymousCloud Extension Public Write Test!";

      // Create and set headers for posting content
      Header headers[] = {
	new BasicHeader("Authorization", "Bearer " + googleBearerToken),
        new BasicHeader("Content-Type", "text/html")
      }; 
      req.setHeaders(headers);
      
      // Connect to GCP services for bucket ACL access
      try {
        req.setEntity(new StringEntity(bucketContent));
        HttpResponse resp = client.execute(req);
        String respHeaders = resp.getStatusLine().toString();

        // If the status is 200, it is public, of 401 then private, otherwise doesn't exist
        if (respHeaders.contains("200 OK")) {
          // Create public write access issue with object written
          IScanIssue publicWriteIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(),
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
            "[Anonymous Cloud] Any Authenticated Google User Writable Google Storage Container",
            "The following bucket object was created in " + BucketName + ": " + bucketItem + ".",
            "High",
            "Certain"
          );
          
          // Add public write bucket access issue
          extCallbacks.addScanIssue(publicWriteIssue);
        }
      } catch (Exception ignore) { }
    }
  }
  
  // Perform anonymous public read access check for a discovered Firebase DB
  private void gcpFirebaseCheck(IHttpRequestResponse messageInfo, List<int[]>matches, String firebaseDb) {
    // Create a client to check Google for the Firebase DB
    HttpClient readClient = HttpClientBuilder.create().build();
    HttpGet readReq = new HttpGet("https://" + firebaseDb + ".json");

    // Connect to GCP services for Firebase DB access
    try {
      HttpResponse readResp = readClient.execute(readReq);
      String readRespHeaders = readResp.getStatusLine().toString();

      // If the status is 200, it is public, otherwise doesn't exist
      if (readRespHeaders.contains("200 OK")) {
          
        // Read the response and get the XML
        BufferedReader rd = new BufferedReader(new InputStreamReader(readResp.getEntity().getContent()));
        String respStr = "";
        String line = "";
          
        // Put XML string together
        while ((line = rd.readLine()) != null) {
          respStr = respStr + line; 
        }
        // Create public access issue with object written
        IScanIssue publicReadIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(),
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
          "[Anonymous Cloud] Publicly Accessible Firebase Database",
          "The following Firebase database is publicly readable: " + firebaseDb + ", and returned: " + respStr,
          "Medium",
          "Certain"
        );
          
          // Add public write bucket access issue
          extCallbacks.addScanIssue(publicReadIssue);
        }
      } catch (Exception ignore) { }
    
    // Create a client to check Google for the Firebase DB
    String firebaseItem = "Burp-AnonymousCloud-" + genRandStr();
    String firebaseContent = "Burp-AnonymousCloud Extension Public Write Test!";
    HttpClient writeClient = HttpClientBuilder.create().build();
    HttpPost writeReq = new HttpPost("https://" + firebaseDb + ".json");

    // Connect to GCP services for Firebase DB access
    try {
      writeReq.setEntity(new StringEntity("{ \"" + firebaseItem + "\": \"" + firebaseContent + "\" }"));
      HttpResponse writeResp = writeClient.execute(writeReq);
      String writeRespHeaders = writeResp.getStatusLine().toString();

      // If the status is 200, it is public, otherwise doesn't exist
      if (writeRespHeaders.contains("200 OK")) {
        // Create public access issue with object written
        IScanIssue publicReadIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(),
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
          "[Anonymous Cloud] Publicly Writable Firebase Database",
          "The Firebase database " + firebaseDb + " had a value of: " + firebaseItem + " written to it.",
          "High",
          "Certain"
        );
          
          // Add public write bucket access issue
          extCallbacks.addScanIssue(publicReadIssue);
        }
      } catch (Exception ignore) { }
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