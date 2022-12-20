/*
 * Name:           Burp Anonymous Cloud
 * Version:        0.1.13
 * Date:           1/21/2020
 * Author:         Josh Berry - josh.berry@codewatch.org
 * Github:         https://github.com/codewatchorg/Burp-AnonymousCloud
 * 
 * Description:    This plugin checks for insecure AWS/Azure/Google application configurations
 * 
 * Contains regex work from Cloud Storage Tester by VirtueSecurity: https://github.com/VirtueSecurity/aws-extender
 * Implemented an idea from https://github.com/0xSearches/sandcastle
 * Implemented AWS checks included in https://gist.github.com/fransr/a155e5bd7ab11c93923ec8ce788e3368
 *
*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.Random;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.File;
import java.net.URL;
import java.net.InetAddress;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.awt.Component;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
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
import org.apache.http.util.EntityUtils;
import java.util.Iterator;
import org.json.JSONObject;
import org.json.JSONArray;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import javax.xml.parsers.*;
import java.io.StringReader;
import javax.naming.directory.InitialDirContext;
import javax.naming.Context;
import java.util.Properties;
import java.util.Arrays;
import java.time.format.DateTimeFormatter;
import java.time.ZonedDateTime;
import java.time.ZoneOffset;

class SubdomainTakeover implements IBurpExtender, Runnable {
  private Thread t;
  private final String domainname;
  private String censysApiKey = "";
  private String censysApiSecret = "";
  private Boolean isShodanSet = false;
  private Boolean isCensysSet = false;
  private Boolean isFileListSet = false;
  private final PrintWriter printOut;
  private ArrayList subdomainList = new ArrayList();
  private static final String certTransUrl = "https://crt.sh/?output=json&q="; 
  private static final String bufferOverUrl = "https://dns.bufferover.run/dns?q=";
  private static final String waybackMachineUrl = "http://web.archive.org/cdx/search/cdx?output=json&url=";
  private static final String hackerTargetUrl = "http://api.hackertarget.com/hostsearch/?q=";
  private static final String shodanBaseUrl = "https://api.shodan.io/dns/domain/";
  private static final String censysBaseUrl = "https://search.censys.io/api/v1/search/";
  private static final Pattern censysCertPattern = Pattern.compile("([\\w.-]*CN\\=(.*)?)", Pattern.CASE_INSENSITIVE );
  private String shodanUrl = "";
  private String censysUrl = "";
  private File subdomainFileList;
  private IBurpExtenderCallbacks extCallbacks;
  private IHttpRequestResponse messageInfo;
  public IExtensionHelpers extHelpers;
  
  public SubdomainTakeover(IBurpExtenderCallbacks callbacks, IHttpRequestResponse messageInfo, String fqdn, PrintWriter burpPrint, String shodan, String censys, File subdomainFile) {
    domainname = fqdn;
    printOut = burpPrint;
    extCallbacks = callbacks;
    this.messageInfo = messageInfo;
    extHelpers = extCallbacks.getHelpers();
    
    try {
      if (subdomainFile.exists() && subdomainFile.length() > 0) {
        subdomainFileList = subdomainFile;
        isFileListSet = true;
      }
    } catch (Exception ignore) {}

    if (shodan.matches("^[a-zA-Z0-9]+")) {
      shodanUrl = shodanBaseUrl + domainname + "?key=" + shodan;
      isShodanSet = true;
    }

    if (censys.length() > 10 && censys.split(":").length == 2) {
      if (censys.split(":")[0].matches("^[a-zA-Z0-9\\-]+") && censys.split(":")[1].matches("^[a-zA-Z0-9]+")) {
        censysApiKey = censys.split(":")[0];
        censysApiSecret = censys.split(":")[1];
        censysUrl = censysBaseUrl + "certificates";
        isCensysSet = true;
      }
    }
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
  
  public void start() {
    if (t == null) {
      t = new Thread(this, domainname);
      t.start();
    }
  }
  
  // Create domains from file list
  private void getListSubdomains() {
    // Try to open and read the file
    try {
      BufferedReader rd = new BufferedReader(new FileReader(subdomainFileList));
      String line = null;
      
      printOut.println("Building a list from the file: " + subdomainFileList.getPath());
      // Loop through each line
      while((line = rd.readLine()) != null) {
          
        // Add to subdomain list if unique
        if (!subdomainList.contains(line + "." + domainname) && !line.equals(domainname) && !line.contains("*")) {
          subdomainList.add(line + "." + domainname);
        }
      }
    } catch (Exception ignore) {}
  }
  
  // Get subdomains from Censys, because they are different than the rest
  private void getCensysSubdomains(String urlType, String srcUrl) {
    // Create a client to check the source URL for domains
    String credentials = Base64.getEncoder().encodeToString((censysApiKey + ":" + censysApiSecret).getBytes(StandardCharsets.UTF_8));
    HttpPost reqSubdomain = new HttpPost(srcUrl);
    HttpClient subdomainClient = HttpClientBuilder.create().build();
    
    // Connect to the site to get subdomains
    try {
      reqSubdomain.setHeader("Authorization", "Basic " + credentials);
      reqSubdomain.setEntity(new StringEntity("{ \"query\": \"" + domainname + "\" }"));
      HttpResponse resp = subdomainClient.execute(reqSubdomain);
      String headers = resp.getStatusLine().toString();
      printOut.println("Building a request to: " + srcUrl);

      // If the status is 200, then hopefully we got JSON or plaintext response with subdomains
      if (headers.contains("200 OK")) {
          
        // Read the response and get the JSON
        BufferedReader rd = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
        String jsonStr = "";
        String line = "";
        while ((line = rd.readLine()) != null) {
          jsonStr = jsonStr + line;
        }

        // Read JSON results
        JSONObject json = new JSONObject(jsonStr);
        JSONArray subdomainObjs = json.getJSONArray("results");
          
        // Loop through our list to build create unique objects
        for (int i = 0; i < subdomainObjs.length(); i++) {
          String obj = subdomainObjs.getJSONObject(i).getString("parsed.subject_dn");
          Matcher censysCertMatcher = censysCertPattern.matcher(obj);
          
          if (censysCertMatcher.find()) {
            String subdomainLine = censysCertMatcher.group(0).split("=")[1];
            
            // Add to subdomain list if unique
            if (!subdomainList.contains(subdomainLine) && !subdomainLine.equals(domainname) && !subdomainLine.contains("*")) {
              subdomainList.add(subdomainLine);
            }
          }
        }
      } else { }
    } catch (Exception ignore) { }
  }
  
  // Get subdomains from common sources
  private void getSubdomains(String urlType, String srcUrl) {
    // Create a client to check the source URL for domains
    HttpGet reqSubdomain = new HttpGet(srcUrl);
    HttpClient subdomainClient = HttpClientBuilder.create().build();
      
    // Connect to the site to get subdomains
    try {
      HttpResponse resp = subdomainClient.execute(reqSubdomain);
      String headers = resp.getStatusLine().toString();
      printOut.println("Building a request to: " + srcUrl);

      // If the status is 200, then hopefully we got JSON or plaintext response with subdomains
      if (headers.contains("200 OK")) {
          
        // Read the response and get the JSON
        BufferedReader rd = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
        
        // Perform lookiup on crt.sh
        if (urlType.contains("crt.sh")) {
          String jsonStr = "";
          String line = "";
          while ((line = rd.readLine()) != null) {
            jsonStr = jsonStr + line;
          }

          // Read JSON results
          JSONArray subdomainObjs = new JSONArray(jsonStr);
          
          // Loop through our list to build create unique objects
          for (int i = 0; i < subdomainObjs.length(); i++) {
            JSONObject obj = subdomainObjs.getJSONObject(i);
            BufferedReader subdomainBuffer = new BufferedReader(new StringReader(obj.getString("name_value")));
            String subdomainLine = "";
            
            // Loop through each line in the result
            while((subdomainLine = subdomainBuffer.readLine()) != null) {
                
              // Add to subdomain list if unique
              if (!subdomainList.contains(subdomainLine) && !subdomainLine.equals(domainname) && !subdomainLine.contains("*")) {
                subdomainList.add(subdomainLine);
              }
            }
          }
          
        // Perform lookup on BufferOver
        } else if (urlType.contains("BufferOver")) {
          String jsonStr = "";
          String line = "";
          while ((line = rd.readLine()) != null) {
            jsonStr = jsonStr + line;
          }

          // Read JSON results
          JSONObject json = new JSONObject(jsonStr);
          JSONArray subdomainAObjs = json.getJSONArray("FDNS_A");
          JSONArray subdomainRObjs = json.getJSONArray("RDNS");
          
          // Loop through our list to build create unique objects
          for (int i = 0; i < subdomainAObjs.length(); i++) {
              
            // Add to subdomain list if unique
            if (!subdomainList.contains(subdomainAObjs.get(i).toString().split(",")[1]) && 
                    !subdomainAObjs.get(i).toString().split(",")[1].equals(domainname) && 
                    !subdomainAObjs.get(i).toString().split(",")[1].contains("*")) {
              subdomainList.add(subdomainAObjs.get(i).toString().split(",")[1]);
            }
          }
          
          // Loop through our list to build create unique objects
          for (int i = 0; i < subdomainRObjs.length(); i++) {
              
            // Add to subdomain list if unique
            if (!subdomainList.contains(subdomainRObjs.get(i).toString().split(",")[1]) && 
                    !subdomainRObjs.get(i).toString().split(",")[1].equals(domainname) && 
                    !subdomainRObjs.get(i).toString().split(",")[1].contains("*")) {
              subdomainList.add(subdomainRObjs.get(i).toString().split(",")[1]);
            }
          }
          
        // Perform lookup on Wayback Machine
        } else if (urlType.contains("WaybackMachine")) {
          String jsonStr = "";
          String line = "";
          int lineCount = 0;
          
          // Loop through each line of output, skip the first line
          while ((line = rd.readLine()) != null) {
            if (lineCount == 0) {
              lineCount++;
            } else {
                
              // Pull out subdomain
              String subdomainUrl = line.split(",")[3].split("/")[2].split(":")[0];
              subdomainUrl = subdomainUrl.replace("\"", "");
              
              // Add to subdomain list if unique
              if (!subdomainList.contains(subdomainUrl) && !subdomainUrl.equals(domainname) && !subdomainUrl.contains("*") && subdomainUrl.contains(domainname)) {
                subdomainList.add(subdomainUrl);
              }
            }
          }
          
        // Perform lookup on Hacker Target
        } else if (urlType.contains("HackerTarget")) {
          String jsonStr = "";
          String line = "";
          
          // Loop through each line of output
          while ((line = rd.readLine()) != null) {

            // Pull out subdomain
            String subdomainUrl = line.split(",")[0];
              
            // Add to subdomain list if unique
            if (!subdomainList.contains(subdomainUrl) && !subdomainUrl.equals(domainname) && !subdomainUrl.contains("*") && !subdomainUrl.contains("error check")) {
              subdomainList.add(subdomainUrl);
            }
          }
          
        // Perform lookup on Shodan
        } else if (urlType.contains("Shodan")) {
          String jsonStr = "";
          String line = "";
          
          while ((line = rd.readLine()) != null) {
            jsonStr = jsonStr + line;
          }

          // Read JSON results
          JSONObject json = new JSONObject(jsonStr);
          JSONArray subdomainObjs = json.getJSONArray("subdomains");
          
          // Loop through our list to build create unique objects
          for (int i = 0; i < subdomainObjs.length(); i++) {
              
            // Add to subdomain list if unique
            if (!subdomainList.contains(subdomainObjs.get(i).toString()) && 
                    !subdomainObjs.get(i).toString().equals(domainname) && 
                    !subdomainObjs.get(i).toString().contains("*")) {
              subdomainList.add(subdomainObjs.get(i).toString() + "." + domainname);
            }
          }
        }
      }
    } catch (Exception ignore) { }
  }
  
  // Return the CNAME status
  private Boolean checkDns(String domain, Pattern cnamePattern) {
    Boolean cnameValid = false;
    
    // Perform the lookup to get CNAMEs
    try {
      Properties env = new Properties();
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
      env.put(Context.PROVIDER_URL, "dns://1.1.1.1");
      InitialDirContext idc = new InitialDirContext(env);
      javax.naming.directory.Attributes attrs = idc.getAttributes(domain, new String[]{"CNAME"});
      javax.naming.directory.Attribute attr = attrs.get("CNAME");
      
      Matcher cnameMatcher = cnamePattern.matcher(attr.get().toString());
      
      // if the cname part matches, then likely vulnerable
      if (cnameMatcher.find()) {
        cnameValid = true;
      }
    } catch (Exception ignore) { }
    
    return cnameValid;
  }
  
  // Return the CNAME value
  private String checkDnsOnly(String domain) {
    String cnameValue = "";
    
    // Perform the lookup to get CNAMEs
    try {
      Properties env = new Properties();
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
      env.put(Context.PROVIDER_URL, "dns://1.1.1.1");
      InitialDirContext idc = new InitialDirContext(env);
      javax.naming.directory.Attributes attrs = idc.getAttributes(domain, new String[]{"CNAME"});
      javax.naming.directory.Attribute attr = attrs.get("CNAME");
      cnameValue = attr.get().toString();
    } catch (Exception ignore) { }
    
    return cnameValue;
  }
  
  // Get subdomains from common sources
  private void scanSubdomains() {
      
    // Create patterns for matching reponses indicating subdomain takeover potential
    Pattern s3Pattern = Pattern.compile("(NoSuchBucket)", Pattern.CASE_INSENSITIVE );
    Pattern s3CnamePattern = Pattern.compile("(\\.s3\\.amazonaws\\.com)", Pattern.CASE_INSENSITIVE );
    Pattern herokuPattern = Pattern.compile("(herokucdn\\.com\\/error-pages\\/no-such-app\\.html)", Pattern.CASE_INSENSITIVE );
    Pattern herokuCnamePattern = Pattern.compile("(\\.herokuapp\\.com|\\.herokudns\\.com|\\.herokussl\\.com)", Pattern.CASE_INSENSITIVE );
    Pattern githubIoPattern = Pattern.compile("(There isn't a GitHub Pages site here\\.)", Pattern.CASE_INSENSITIVE );
    Pattern githubCnamePattern = Pattern.compile("(\\.github\\.io)", Pattern.CASE_INSENSITIVE );

    // Loop through the list of subdomains to test
    for (int i = 0; i < subdomainList.size(); i++) {
      Boolean subdomainSuccess = false;
       
      // Create a client to check for subdomain takeover
      HttpGet reqSubdomainHttp = new HttpGet("http://" + subdomainList.get(i));
      HttpClient subdomainClientHttp = HttpClientBuilder.create().build();
      
      // Connect to the site via http to get response for potential subdomain takeover
      try {
        HttpResponse resp = subdomainClientHttp.execute(reqSubdomainHttp);
        String headers = resp.getStatusLine().toString();
        
        // If the status is 404, then it might be vulnerable
        if (headers.contains("404 Not Found")) {
          String respStr = EntityUtils.toString(resp.getEntity());
          Matcher s3Matcher = s3Pattern.matcher(respStr);
          Matcher herokuMatcher = herokuPattern.matcher(respStr);
          Matcher githubIoMatcher = githubIoPattern.matcher(respStr);
          
          // If there is a match for the s3 pattern then it is probably vulnerable
          if (s3Matcher.find()) {

            // Validate CNAME
            if (checkDns(subdomainList.get(i).toString(), s3CnamePattern)) {
              printOut.println("Potential subdomain takeover of an S3 bucket found for: http://" + subdomainList.get(i));
              URL subdomainUrl = new URL("http://" + subdomainList.get(i));
              
              // Create an issue from the finding
              List<int[]> s3SubdomainMatches = getMatches(messageInfo.getResponse(), s3Matcher.group(0).getBytes());
              IScanIssue subdomainS3IdIssue = new CustomScanIssue(
                messageInfo.getHttpService(),
                subdomainUrl, 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, s3SubdomainMatches) },
                "[Anonymous Cloud] Subdomain Takeover - " + subdomainList.get(i),
                "The response for the following subdomain returned 'NoSuchDomain', indicating vulnerability to subdomain takeover via s3 bucket.<BR>See: also: https://github.com/EdOverflow/can-i-take-over-xyz.",
                "High",
                "Firm"
              );
              
              // Add the S3 subdomain takeover issue
              extCallbacks.addScanIssue(subdomainS3IdIssue);
              subdomainSuccess = true;
            }
          }

          // If there is a match for the Heroku pattern then it is probably vulnerable
          if (herokuMatcher.find()) {

            // Validate CNAME
            if (checkDns(subdomainList.get(i).toString(), herokuCnamePattern)) {
              printOut.println("Potential subdomain takeover of a Heroku app found for: http://" + subdomainList.get(i));
              URL subdomainUrl = new URL("http://" + subdomainList.get(i));
             
              // Create an issue from the finding
              List<int[]> herokuSubdomainMatches = getMatches(messageInfo.getResponse(), herokuMatcher.group(0).getBytes());
              IScanIssue subdomainHerokuIdIssue = new CustomScanIssue(
                messageInfo.getHttpService(),
                subdomainUrl, 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, herokuSubdomainMatches) },
                "[Anonymous Cloud] Subdomain Takeover - " + subdomainList.get(i),
                "The response for the following subdomain returned 'herokucdn.com/error-pages/no-such-app.html', indicating vulnerability to subdomain takeover via Heroku app.<BR>See: also: https://github.com/EdOverflow/can-i-take-over-xyz.",
                "High",
                "Firm"
              );
              
              // Add the Heroku subdomain takeover issue
              extCallbacks.addScanIssue(subdomainHerokuIdIssue);
              subdomainSuccess = true;
            }
          }
            
          // If there is a match for the Github.io pattern then it is probably vulnerable
          if (githubIoMatcher.find()) {

            // Validate CNAME
            if (checkDns(subdomainList.get(i).toString(), githubCnamePattern)) {
              printOut.println("Potential subdomain takeover of a Github.io pages result for: http://" + subdomainList.get(i));
              URL subdomainUrl = new URL("http://" + subdomainList.get(i));
              
              // Create an issue from the finding
              List<int[]> githubIoSubdomainMatches = getMatches(messageInfo.getResponse(), githubIoMatcher.group(0).getBytes());
              IScanIssue subdomainGithubIoIdIssue = new CustomScanIssue(
                messageInfo.getHttpService(),
                subdomainUrl, 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, githubIoSubdomainMatches) },
                "[Anonymous Cloud] Subdomain Takeover - " + subdomainList.get(i),
                "The response for the following subdomain returned 'There isn't a GitHub Pages site here.', indicating vulnerability to subdomain takeover via Github.io pages.<BR>See: also: https://github.com/EdOverflow/can-i-take-over-xyz.",
                "High",
                "Firm"
              );
              
              // Add the Heroku subdomain takeover issue
              extCallbacks.addScanIssue(subdomainGithubIoIdIssue);
              subdomainSuccess = true;
            }
          }
        }
      } catch (Exception ignore) { }
       
      // Try again with https if we didn't already find something
      if (!subdomainSuccess) {
        // Create an http client to check for subdomain takeover
        HttpGet reqSubdomainHttps = new HttpGet("https://" + subdomainList.get(i));
        HttpClient subdomainClientHttps = HttpClientBuilder.create().build();
      
        // Connect to the site via https to get response for potential subdomain takeover
        try {
          HttpResponse resp = subdomainClientHttps.execute(reqSubdomainHttps);
          String headers = resp.getStatusLine().toString();

          // If the status is 200, then hopefully we got JSON or plaintext response with subdomains
          if (headers.contains("404 Not Found")) {
            String respStr = EntityUtils.toString(resp.getEntity());
            Matcher s3Matcher = s3Pattern.matcher(respStr);
            Matcher herokuMatcher = herokuPattern.matcher(respStr);
            Matcher githubIoMatcher = githubIoPattern.matcher(respStr);
              
            // If there is a match for the s3 pattern then it is probably vulnerable
            if (s3Matcher.find()) {
                
              // Validate CNAME
              if (checkDns(subdomainList.get(i).toString(), s3CnamePattern)) {
                printOut.println("Potential subdomain takeover of an S3 bucket found for: https://" + subdomainList.get(i));
                URL subdomainUrl = new URL("https://" + subdomainList.get(i));
              
                // Create an issue from the finding
                List<int[]> s3SubdomainMatches = getMatches(messageInfo.getResponse(), s3Matcher.group(0).getBytes());
                IScanIssue subdomainS3IdIssue = new CustomScanIssue(
                  messageInfo.getHttpService(),
                  subdomainUrl, 
                  new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, s3SubdomainMatches) },
                  "[Anonymous Cloud] Subdomain Takeover - " + subdomainList.get(i),
                  "The response for the following subdomain returned 'NoSuchDomain', indicating vulnerability to subdomain takeover via s3 bucket.<BR>See: also: https://github.com/EdOverflow/can-i-take-over-xyz.",
                  "High",
                  "Firm"
                );
              
                // Add the S3 subdomain takeover issue
                extCallbacks.addScanIssue(subdomainS3IdIssue);
                subdomainSuccess = true;
              }
            }
             
            // If there is a match for the Heroku pattern then it is probably vulnerable
            if (herokuMatcher.find()) {
              
              // Validate CNAME
              if (checkDns(subdomainList.get(i).toString(), herokuCnamePattern)) {
                printOut.println("Potential subdomain takeover of a Heroku app found for: https://" + subdomainList.get(i));
                URL subdomainUrl = new URL("https://" + subdomainList.get(i));
            
                // Create an issue from the finding
                List<int[]> herokuSubdomainMatches = getMatches(messageInfo.getResponse(), herokuMatcher.group(0).getBytes());
                IScanIssue subdomainHerokuIdIssue = new CustomScanIssue(
                  messageInfo.getHttpService(),
                  subdomainUrl, 
                  new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, herokuSubdomainMatches) },
                  "[Anonymous Cloud] Subdomain Takeover - " + subdomainList.get(i),
                  "The response for the following subdomain returned 'herokucdn.com/error-pages/no-such-app.html', indicating vulnerability to subdomain takeover via Heroku app.<BR>See: also: https://github.com/EdOverflow/can-i-take-over-xyz.",
                  "High",
                  "Firm"
                );
              
                // Add the Heroku subdomain takeover issue
                extCallbacks.addScanIssue(subdomainHerokuIdIssue);
                subdomainSuccess = true;
              }
            }
             
            // If there is a match for the Github.io pattern then it is probably vulnerable
            if (githubIoMatcher.find()) {

              // Validate CNAME
              if (checkDns(subdomainList.get(i).toString(), githubCnamePattern)) {
                printOut.println("Potential subdomain takeover of a Github.io pages result for: https://" + subdomainList.get(i));
                URL subdomainUrl = new URL("https://" + subdomainList.get(i));
            
                // Create an issue from the finding
                List<int[]> githubIoSubdomainMatches = getMatches(messageInfo.getResponse(), githubIoMatcher.group(0).getBytes());
                IScanIssue subdomainGithubIoIdIssue = new CustomScanIssue(
                  messageInfo.getHttpService(),
                  subdomainUrl, 
                  new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, githubIoSubdomainMatches) },
                  "[Anonymous Cloud] Subdomain Takeover - " + subdomainList.get(i),
                  "The response for the following subdomain returned 'There isn't a GitHub Pages site here.', indicating vulnerability to subdomain takeover via Github.io pages.<BR>See: also: https://github.com/EdOverflow/can-i-take-over-xyz.",
                  "High",
                  "Firm"
                );
              
                // Add the Github Pages subdomain takeover issue
                extCallbacks.addScanIssue(subdomainGithubIoIdIssue);
                subdomainSuccess = true;
              }
            }
          }
        } catch (Exception ignore) { }
      }
    }
  }
  
  // Get subdomains from common sources
  private void scanDnsSubdomains() {
      
    // Create patterns for Azure resources
    Pattern[] azurePatterns = {
      Pattern.compile("(\\.cloudapp\\.net)", Pattern.CASE_INSENSITIVE ),
      Pattern.compile("(\\.cloudapp\\.azure\\.com)", Pattern.CASE_INSENSITIVE ),
      Pattern.compile("(\\.azurewebsites\\.com)", Pattern.CASE_INSENSITIVE ),
      Pattern.compile("(\\.blob\\.core\\.windows\\.net)", Pattern.CASE_INSENSITIVE ),
      Pattern.compile("(\\.azure-api\\.com)", Pattern.CASE_INSENSITIVE ),
      Pattern.compile("(\\.azurecontainer\\.io)", Pattern.CASE_INSENSITIVE ),
      Pattern.compile("(\\.database\\.windows\\.net)", Pattern.CASE_INSENSITIVE ),
      Pattern.compile("(\\.azuredatalakestore\\.net)", Pattern.CASE_INSENSITIVE ),
      Pattern.compile("(\\.search\\.windows\\.net)", Pattern.CASE_INSENSITIVE ),
      Pattern.compile("(\\.redis\\.cache\\.windows\\.net)", Pattern.CASE_INSENSITIVE )
    };
    
    // Create strings of Azure resources
    String[] azureDomains = {
      ".cloudapp.net",
      ".cloudapp.azure.com",
      ".azurewebsites.com",
      ".blob.core.windows.net",
      ".azure-api.com",
      ".azurecontainer.io",
      ".database.windows.net",
      ".azuredatalakestore.net",
      ".search.windows.net",
      ".redis.cache.windows.net"
    };

    // Loop through the list of subdomains to test
    for (int i = 0; i < subdomainList.size(); i++) {
        
      // Get cname result
      String cnameResult = checkDnsOnly(subdomainList.get(i).toString());

      // Loop through patterns if anything was returned
      if (cnameResult.length() > 10) {
        for (int j = 0; j < azurePatterns.length; j++) {
          Matcher azureMatcher = azurePatterns[j].matcher(cnameResult);
          
          // Check against the pattern
          if (azureMatcher.find()) {
              
            // Create an http client to check for subdomain takeover
            String azureDomain = subdomainList.get(i).toString().split("\\.")[0];
            String[] testing = subdomainList.get(i).toString().split("\\.");
            HttpGet reqSubdomainHttp = new HttpGet("http://" + azureDomain + azureDomains[j]);
            HttpClient subdomainClientHttp = HttpClientBuilder.create().build();
            Boolean isNotResponding = true;
      
            // Connect to the site via https to get response for potential subdomain takeover
            try {
              HttpResponse resp = subdomainClientHttp.execute(reqSubdomainHttp);
              String headers = resp.getStatusLine().toString();
              isNotResponding = false;
            } catch (Exception ignore) { }
            
            // If CNAME result points to Azure resource but website does not respond, potentially vulnerable
            if (isNotResponding) {
              try {
                printOut.println("Potential subdomain takeover of an Azure for: https://" + subdomainList.get(i));
                // Create an issue from the finding
                URL subdomainUrl = new URL("https://" + subdomainList.get(i));
                List<int[]> azureSubdomainMatches = getMatches(messageInfo.getResponse(), azureMatcher.group(0).getBytes());
                IScanIssue subdomainAzureIdIssue = new CustomScanIssue(
                  messageInfo.getHttpService(),
                  subdomainUrl, 
                  new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, azureSubdomainMatches) },
                  "[Anonymous Cloud] Subdomain Takeover - " + subdomainList.get(i),
                  "A CNAME points to an Azure resource that does not respond the a web request, indicating vulnerability to subdomain takeover for: " + azureDomain + azureDomains[j] + "<BR>See: also: https://github.com/EdOverflow/can-i-take-over-xyz.",
                  "High",
                  "Firm"
                );
              
                // Add the Azure subdomain takeover issue
                extCallbacks.addScanIssue(subdomainAzureIdIssue);
              } catch (Exception ignore) { }
            }
          }
        }
      }
    }
  }
    
  @Override
  public void run() {
      
    printOut.println("Beginning subdomain scanning, gathering subdomain lists.");
    // Get subdomains from a file if one was provided
    if (isFileListSet) {
      getListSubdomains();
    }
      
    // Get subdomains from open sources
    getSubdomains("crt.sh", certTransUrl + domainname);
    getSubdomains("BufferOver", bufferOverUrl + domainname);
    getSubdomains("WaybackMachine", waybackMachineUrl + domainname);
    getSubdomains("HackerTarget", hackerTargetUrl + domainname);
    
    // if a Shodan API key was provided, get subdomains
    if (isShodanSet) {
      getSubdomains("Shodan", shodanUrl);
    }
    
    // if a Censys API key was provided, get subdomains
    if (isCensysSet) {
      getCensysSubdomains("Censys", censysUrl);
    }
    
    // Begin scan based on HTTP
    printOut.println("Beginning HTTP/HTTPS subdomain scanning for AWS S3/Heroku/Github.");
    scanSubdomains();
    
    // Begin scan based on DNS
    printOut.println("Beginning DNS subdomain scanning for Azure.");
    scanDnsSubdomains();
    
    printOut.println("Subdomain scanning has completed.");
  }
  
  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    throw new UnsupportedOperationException("Not supported yet."); 
  }
}

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab {

  // Setup extension wide variables
  public IBurpExtenderCallbacks extCallbacks;
  public IExtensionHelpers extHelpers;
  private static final String burpAnonCloudVersion = "0.1.13";
  private static final Pattern S3BucketPattern = Pattern.compile("((?:\\w+://)?(?:([\\w.-]+)\\.s3[\\w.-]*\\.amazonaws\\.com|s3(?:[\\w.-]*\\.amazonaws\\.com(?:(?::\\d+)?\\\\?/)*|://)([\\w.-]+))(?:(?::\\d+)?\\\\?/)?(?:.*?\\?.*Expires=(\\d+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern GoogleBucketPattern = Pattern.compile("((?:\\w+://)?(?:([\\w.-]+)\\.storage[\\w-]*\\.googleapis\\.com|(?:(?:console\\.cloud\\.google\\.com/storage/browser/|storage\\.cloud\\.google\\.com|storage[\\w-]*\\.googleapis\\.com)(?:(?::\\d+)?\\\\?/)*|gs://)([\\w.-]+))(?:(?::\\d+)?\\\\?/([^\\s?'\"#]*))?(?:.*\\?.*Expires=(\\d+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern GcpFirebase = Pattern.compile("([\\w.-]+\\.firebaseio\\.com)", Pattern.CASE_INSENSITIVE );
  private static final Pattern GcpFirestorePattern = Pattern.compile("(firestore\\.googleapis\\.com.*)", Pattern.CASE_INSENSITIVE );
  private static final Pattern AzureBucketPattern = Pattern.compile("(([\\w.-]+\\.blob\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureTablePattern = Pattern.compile("(([\\w.-]+\\.table\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureQueuePattern = Pattern.compile("(([\\w.-]+\\.queue\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureFilePattern = Pattern.compile("(([\\w.-]+\\.file\\.core\\.windows\\.net(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern AzureCosmosPattern = Pattern.compile("(([\\w.-]+\\.documents\\.azure\\.com(?::\\d+)?\\\\?/[\\w.-]+)(?:.*?\\?.*se=([\\w%-]+))?)", Pattern.CASE_INSENSITIVE);
  private static final Pattern ParseServerPattern = Pattern.compile("(X\\-Parse\\-Application\\-Id:)", Pattern.CASE_INSENSITIVE);
  public JPanel anonCloudPanel;
  private String awsAccessKey = "";
  private String awsSecretAccessKey = "";
  private String googleBearerToken = "";
  private String shodanApiKey = "";
  private String censysApiKey = "";
  private String censysApiSecret = "";
  private String anonCloudConfig = "anon-cloud-config.conf";
  private static final String GoogleValidationUrl = "https://storage.googleapis.com/storage/v1/b/";
  private static final String GoogleBucketUploadUrl = "https://storage.googleapis.com/upload/storage/v1/b/";
  private Boolean isAwsAuthSet = false;
  private Boolean isGoogleAuthSet = false;
  private Boolean isShodanApiSet = false;
  private Boolean isCensysApiSet = false;
  private Boolean isSubdomainTakeoverSet = false;
  private Boolean isBucketSubsSet = false;
  private ArrayList SubdomainThreads = new ArrayList();
  private File subdomainFileList;
  private File bucketFileList;
  private ArrayList bucketList = new ArrayList();
  private ArrayList firebaseList = new ArrayList();
  private ArrayList firebaseCheckList = new ArrayList();
  private ArrayList firestoreCheckList = new ArrayList();
  private ArrayList bucketCheckList = new ArrayList();
  private ArrayList siteOnBucketCheckList = new ArrayList();
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
    JLabel anonCloudSubdomainTakeoverLabel = new JLabel();
    JLabel anonCloudSubdomainTakeoverDescLabel = new JLabel();
    JLabel anonCloudSubdomainShodanLabel = new JLabel();
    JLabel anonCloudSubdomainShodanDescLabel = new JLabel();
    JLabel anonCloudSubdomainCensysLabel = new JLabel();
    JLabel anonCloudSubdomainCensysDescLabel = new JLabel();
    JLabel anonCloudSubdomainCensysSecretLabel = new JLabel();
    JLabel anonCloudSubdomainCensysSecretDescLabel = new JLabel();
    JLabel anonCloudSubdomainTakeoverListLabel = new JLabel();
    JLabel anonCloudSubdomainTakeoverListDescLabel = new JLabel();
    JLabel anonCloudBucketSubsLabel = new JLabel();
    JLabel anonCloudBucketSubsDescLabel = new JLabel();
    final JCheckBox anonCloudSubdomainTakeoverCheck = new JCheckBox();
    JLabel anonCloudBucketSubsListLabel = new JLabel();
    JLabel anonCloudBucketSubsListDescLabel = new JLabel();
    final JCheckBox anonCloudBucketSubsCheck = new JCheckBox();
    final JTextField anonCloudAwsKeyText = new JTextField();
    final JTextField anonCloudAwsSecretKeyText = new JTextField();
    final JTextField anonCloudGoogleBearerText = new JTextField();
    final JTextField anonCloudSubdomainShodanText = new JTextField();
    final JTextField anonCloudSubdomainCensysText = new JTextField();
    final JTextField anonCloudSubdomainCensysSecretText = new JTextField();
    final JButton anonCloudSubdomainTakeoverListButton = new JButton("Subdomain List");
    final JButton anonCloudBucketSubsListButton = new JButton("Bucket List");
    JButton anonCloudSetHeaderBtn = new JButton("Set Configuration");
    JLabel anonCloudSetHeaderDescLabel = new JLabel();
    
    // Set values for labels, panels, locations, for AWS stuff
    // AWS Access Key GUI
    anonCloudAwsKeyLabel.setText("AWS Access Key:");
    anonCloudAwsKeyDescLabel.setText("Any AWS authenticated user test: AWS Access Key.");
    anonCloudAwsKeyLabel.setBounds(16, 15, 145, 20);
    anonCloudAwsKeyText.setBounds(166, 12, 310, 26);
    anonCloudAwsKeyDescLabel.setBounds(606, 15, 600, 20);
    
    // AWS Secret Access Key GUI
    anonCloudAwsSecretKeyLabel.setText("AWS Secret Access Key:");
    anonCloudAwsSecretKeyDescLabel.setText("Any AWS authenticated user test: AWS Secret Access Key.");
    anonCloudAwsSecretKeyLabel.setBounds(16, 50, 145, 20);
    anonCloudAwsSecretKeyText.setBounds(166, 47, 310, 26);
    anonCloudAwsSecretKeyDescLabel.setBounds(606, 50, 600, 20);
    
    // Set values for labels, panels, locations, for Google stuff
    // Google Bearer Token
    anonCloudGoogleBearerLabel.setText("Google Bearer Token:");
    anonCloudGoogleBearerDescLabel.setText("Any Google authenticated user test: Google Bearer Token (use 'gcloud auth print-access-token')");
    anonCloudGoogleBearerLabel.setBounds(16, 85, 145, 20);
    anonCloudGoogleBearerText.setBounds(166, 82, 310, 26);
    anonCloudGoogleBearerDescLabel.setBounds(606, 85, 600, 20);
    
    // Set values for labels, panels, locations, for Shodan stuff
    // Shodan API key
    anonCloudSubdomainShodanLabel.setText("Shodan API Key:");
    anonCloudSubdomainShodanDescLabel.setText("Shodan API key for use with subdomain takeover testing.");
    anonCloudSubdomainShodanLabel.setBounds(16, 120, 145, 20);
    anonCloudSubdomainShodanText.setBounds(166, 117, 310, 26);
    anonCloudSubdomainShodanDescLabel.setBounds(606, 120, 600, 20);
    
    // Set values for labels, panels, locations, for Censys.io stuff
    // Censys API key
    anonCloudSubdomainCensysLabel.setText("Censys API Key:");
    anonCloudSubdomainCensysDescLabel.setText("Censys API key for use with subdomain takeover testing.");
    anonCloudSubdomainCensysLabel.setBounds(16, 155, 145, 20);
    anonCloudSubdomainCensysText.setBounds(166, 152, 310, 26);
    anonCloudSubdomainCensysDescLabel.setBounds(606, 155, 600, 20);
    
    // Set values for labels, panels, locations, for Censys.io stuff
    // Censys API Secret
    anonCloudSubdomainCensysSecretLabel.setText("Censys API Secret:");
    anonCloudSubdomainCensysSecretDescLabel.setText("Censys API Secret for use with subdomain takeover testing.");
    anonCloudSubdomainCensysSecretLabel.setBounds(16, 190, 145, 20);
    anonCloudSubdomainCensysSecretText.setBounds(166, 187, 310, 26);
    anonCloudSubdomainCensysSecretDescLabel.setBounds(606, 190, 600, 20);
    
    // Checkbox for Subdomain Takeovers
    anonCloudSubdomainTakeoverLabel.setText("Enable Subdomain Takeover:");
    anonCloudSubdomainTakeoverDescLabel.setText("Automate discovery of subdomains that might be vulnerable to takeover.");
    anonCloudSubdomainTakeoverLabel.setBounds(16, 225, 145, 20);
    anonCloudSubdomainTakeoverCheck.setBounds(456, 222, 20, 26);
    anonCloudSubdomainTakeoverDescLabel.setBounds(606, 225, 600, 20);
    
    // Checkbox for Subdomain Takeovers
    anonCloudSubdomainTakeoverListLabel.setText("Subdomain List:");
    anonCloudSubdomainTakeoverListDescLabel.setText("File to provide subdomains (will append each item with .<domain>.com/net/org/etc).");
    anonCloudSubdomainTakeoverListLabel.setBounds(16, 260, 145, 20);
    anonCloudSubdomainTakeoverListButton.setBounds(166, 257, 310, 26);
    anonCloudSubdomainTakeoverListDescLabel.setBounds(606, 260, 600, 20);
    
    // Checkbox for checking additional bucket names
    anonCloudBucketSubsLabel.setText("Extra Bucket Checks:");
    anonCloudBucketSubsDescLabel.setText("If a valid bucket/Firebase DB is found, append various common names to discover additional resources.");
    anonCloudBucketSubsLabel.setBounds(16, 295, 145, 20);
    anonCloudBucketSubsCheck.setBounds(456, 292, 20, 26);
    anonCloudBucketSubsDescLabel.setBounds(606, 295, 600, 20);
    
    // Checkbox for checking additional bucket names
    anonCloudBucketSubsListLabel.setText("Bucket List:");
    anonCloudBucketSubsListDescLabel.setText("File to provide bucket/Firebase DB names to append to a valid bucket/DB.");
    anonCloudBucketSubsListLabel.setBounds(16, 330, 145, 20);
    anonCloudBucketSubsListButton.setBounds(166, 327, 310, 26);
    anonCloudBucketSubsListDescLabel.setBounds(606, 330, 600, 20);
    
    // Create button for setting options
    anonCloudSetHeaderDescLabel.setText("Enable access configuration.");
    anonCloudSetHeaderDescLabel.setBounds(606, 365, 600, 20);
    anonCloudSetHeaderBtn.setBounds(166, 365, 310, 26);
    
    // Print extension header
    printHeader();
    
    File anonCloudConfigFile = new File(extCallbacks.getExtensionFilename().replace("AnonymousCloud.jar", "") + anonCloudConfig);
    if (anonCloudConfigFile.isFile()) {
        printOut.println("Reading configuration file: " + extCallbacks.getExtensionFilename().replace("AnonymousCloud.jar", "") + anonCloudConfig.toString());
        
        try {
            BufferedReader br = new BufferedReader(new FileReader(extCallbacks.getExtensionFilename().replace("AnonymousCloud.jar", "") + anonCloudConfig));
               
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                String configLine[] = line.split(":",0);
                if (configLine[0].equals("AWSAccessKey")) {
                    awsAccessKey = configLine[1];
                } else if (configLine[0].equals("AWSSecretKey")) {
                    awsSecretAccessKey = configLine[1];
                } else if (configLine[0].equals("GoogleBearerToken")) {
                    googleBearerToken = configLine[1];
                    
                    // Add Google Bearer Token if set
                    if (googleBearerToken.matches("^ya29\\.[0-9A-Za-z\\-_]+")) {
                        isGoogleAuthSet = true;
                        anonCloudGoogleBearerText.setText(googleBearerToken);
                    }
                } else if (configLine[0].equals("ShodanKey")) {
                    shodanApiKey = configLine[1];
                    
                    // Add Shodan API key if set
                    if (shodanApiKey.matches("^[a-zA-Z0-9]+")) {
                        isShodanApiSet = true;
                        anonCloudSubdomainShodanText.setText(shodanApiKey);
                    }
                } else if (configLine[0].equals("CensysKey")) {
                    censysApiKey = configLine[1];
                } else if (configLine[0].equals("CensysSecret")) {
                    censysApiSecret = configLine[1];
                } else if (configLine[0].equals("SubdomainTakeover")) {
                    if (configLine[1].equals("true")) {
                        anonCloudSubdomainTakeoverCheck.setSelected(true);
                        isSubdomainTakeoverSet = true;
                    }
                } else if (isSubdomainTakeoverSet && configLine[0].equals("SubdomainList")) {
                    File subdomainFile = new File(configLine[1] + ":" + configLine[2]);
                    
                    if (subdomainFile.length() > 0) {
                        subdomainFileList = subdomainFile;
                        printOut.println("Setting subdomain file to: " + subdomainFile.toString());
                    }
                } else if (configLine[0].equals("ExtraBuckets")) {
                    if (configLine[1].equals("true")) {
                        anonCloudBucketSubsCheck.setSelected(true);
                        isBucketSubsSet = true;
                    }
                } else if (isBucketSubsSet && configLine[0].equals("ExtraBucketsList")) {
                    File bucketFile = new File(configLine[1] + ":" + configLine[2]);
                    
                    if (bucketFile.length() > 0) {
                        bucketFileList = bucketFile;
                        printOut.println("Setting buckets file to: " + bucketFile.toString());
                    }
                }      
            }
            
            // Auth to AWS
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
                anonCloudAwsKeyText.setText(awsAccessKey);
                anonCloudAwsSecretKeyText.setText(awsSecretAccessKey);
            }
        
            // Add Censys API key if set
            if (censysApiKey.matches("^[a-zA-Z0-9\\-]+") && censysApiSecret.matches("^[a-zA-Z0-9]+")) {
                isCensysApiSet = true;
                anonCloudSubdomainCensysText.setText(censysApiKey);
                anonCloudSubdomainCensysSecretText.setText(censysApiSecret);
            }
        } catch (Exception ignore) { }
    }
    
    // Process and set subdomain file list
    anonCloudSubdomainTakeoverListButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
          
        // Select the file
        JFileChooser selectFile = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Text files only", "txt");
        selectFile.setFileFilter(filter);
        int returnFile = selectFile.showDialog(anonCloudPanel, "Subdomain List");
        
        // If a file was chosen, process it
        if (returnFile == JFileChooser.APPROVE_OPTION) {
          File subdomainFile = selectFile.getSelectedFile();
          
          if (subdomainFile.length() > 0) {
            subdomainFileList = subdomainFile;
            printOut.println("Setting subdomain file to: " + subdomainFile.toString() + "\n");
          }
        }
      }
    });
    
    // Process and set bucket append/prepend file list
    anonCloudBucketSubsListButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
          
        // Select the file
        JFileChooser selectFile = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Text files only", "txt");
        selectFile.setFileFilter(filter);
        int returnFile = selectFile.showDialog(anonCloudPanel, "Bucket List");
        
        // If a file was chosen, process it
        if (returnFile == JFileChooser.APPROVE_OPTION) {
          File bucketFile = selectFile.getSelectedFile();
          
          if (bucketFile.length() > 0) {
            bucketFileList = bucketFile;
            printOut.println("Setting buckets file to: " + bucketFile.toString() + "\n");
          }
        }
      }
    });
    
    // Process and set configuration options
    anonCloudSetHeaderBtn.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        awsAccessKey = anonCloudAwsKeyText.getText();
        awsSecretAccessKey = anonCloudAwsSecretKeyText.getText();
        googleBearerToken = anonCloudGoogleBearerText.getText();
        shodanApiKey = anonCloudSubdomainShodanText.getText();
        censysApiKey = anonCloudSubdomainCensysText.getText();
        censysApiSecret = anonCloudSubdomainCensysSecretText.getText();
        
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
        
        // Add Google Bearer Token if set
        if (googleBearerToken.matches("^ya29\\.[0-9A-Za-z\\-_]+")) {
          isGoogleAuthSet = true;
        }
        
        // Add Shodan API key if set
        if (shodanApiKey.matches("^[a-zA-Z0-9]+")) {
          isShodanApiSet = true;
        }
        
        // Add Censys API key if set
        if (censysApiKey.matches("^[a-zA-Z0-9\\-]+") && censysApiSecret.matches("^[a-zA-Z0-9]+")) {
          isCensysApiSet = true;
        }
            
        // Check for Subdomain Takeover being enabled
        if (anonCloudSubdomainTakeoverCheck.isSelected()){
          isSubdomainTakeoverSet = true;
        }
        
        // Check for extra bucket checks being enabled
        if (anonCloudBucketSubsCheck.isSelected()){
          isBucketSubsSet = true;
        }
        
        try {
            printOut.println("Writing config file: " + extCallbacks.getExtensionFilename().replace("AnonymousCloud.jar", "") + anonCloudConfig.toString() + "\n");
            PrintWriter anonCloudConfigFileObj = new PrintWriter(extCallbacks.getExtensionFilename().replace("AnonymousCloud.jar", "") + anonCloudConfig);
            String configText = "AWSAccessKey:" + awsAccessKey + "\nAWSSecretKey:" + awsSecretAccessKey + "\nGoogleBearerToken:" + googleBearerToken + "\nShodanKey:" + shodanApiKey + "\nCensysKey:" + censysApiKey + "\nCensysSecret:" + censysApiSecret + "\nSubdomainTakeover:" + isSubdomainTakeoverSet.toString() + "\nSubdomainList:" + subdomainFileList.toString() + "\nExtraBuckets:" + isBucketSubsSet.toString() + "\nExtraBucketsList:" + bucketFileList.toString();
            anonCloudConfigFileObj.println(configText);
            anonCloudConfigFileObj.close();
        } catch (Exception ignore) { }
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
    anonCloudPanel.add(anonCloudSubdomainTakeoverLabel);
    anonCloudPanel.add(anonCloudSubdomainTakeoverDescLabel);
    anonCloudPanel.add(anonCloudSubdomainTakeoverCheck);
    anonCloudPanel.add(anonCloudSubdomainShodanLabel);
    anonCloudPanel.add(anonCloudSubdomainShodanDescLabel);
    anonCloudPanel.add(anonCloudSubdomainShodanText);
    anonCloudPanel.add(anonCloudSubdomainCensysLabel);
    anonCloudPanel.add(anonCloudSubdomainCensysDescLabel);
    anonCloudPanel.add(anonCloudSubdomainCensysText);
    anonCloudPanel.add(anonCloudSubdomainCensysSecretLabel);
    anonCloudPanel.add(anonCloudSubdomainCensysSecretDescLabel);
    anonCloudPanel.add(anonCloudSubdomainCensysSecretText);
    anonCloudPanel.add(anonCloudSubdomainTakeoverListLabel);
    anonCloudPanel.add(anonCloudSubdomainTakeoverListDescLabel);
    anonCloudPanel.add(anonCloudSubdomainTakeoverListButton);
    anonCloudPanel.add(anonCloudBucketSubsLabel);
    anonCloudPanel.add(anonCloudBucketSubsDescLabel);
    anonCloudPanel.add(anonCloudBucketSubsCheck);
    anonCloudPanel.add(anonCloudBucketSubsListLabel);
    anonCloudPanel.add(anonCloudBucketSubsListDescLabel);
    anonCloudPanel.add(anonCloudBucketSubsListButton);
    anonCloudPanel.add(anonCloudSetHeaderBtn);
    anonCloudPanel.add(anonCloudSetHeaderDescLabel);
    
    
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
        
      // Start thread for subdomain takeovers
      if (isSubdomainTakeoverSet) {
        String fqdn = extHelpers.analyzeRequest(messageInfo).getUrl().getHost();
        String[] strUrl = fqdn.split("\\.");
        
        // If a thread has not already been started for this FQDN, then start one, but only if wildcard DNS fails
        if (!SubdomainThreads.contains(strUrl[strUrl.length-2] + "." + strUrl[strUrl.length-1])) {
          SubdomainThreads.add(strUrl[strUrl.length-2] + "." + strUrl[strUrl.length-1]);
            
          // Perform a lookup on a non-existent DNS address first to make sure wildcard responses are not on
          InetAddress[] firstDnsTest;
          Boolean lookupStatus = false;
          String wildcardTest = Base64.getEncoder().encodeToString((genRandStr()).getBytes(StandardCharsets.UTF_8)).replace("=", "").replace("/", "").replace("+", "");

          // Lookup the address
          try {
            firstDnsTest = InetAddress.getAllByName(wildcardTest + "." + strUrl[strUrl.length-2] + "." + strUrl[strUrl.length-1]);

            // If we got a response, set status to true
            if (firstDnsTest.length > 0) {
              lookupStatus = true;
            }
          } catch (Exception ignore) { }
    
          // If the lookup failed, wildcard responses are not on and we can proceed
          if (!lookupStatus) {
            String censysCredential = censysApiKey + ":" + censysApiSecret;
            SubdomainTakeover t = new SubdomainTakeover(extCallbacks, messageInfo, strUrl[strUrl.length-2] + "." + strUrl[strUrl.length-1], printOut, shodanApiKey, censysCredential, subdomainFileList);
            t.start();
          }
        }
      }
        
      // Setup default request/response body variables
      String respRaw = new String(messageInfo.getResponse());
      String reqRaw = new String(messageInfo.getRequest());
      String respBody = respRaw.substring(extHelpers.analyzeResponse(messageInfo.getResponse()).getBodyOffset());
      
      // Create patter matchers for each type
      Matcher S3BucketMatch = S3BucketPattern.matcher(respBody);
      Matcher GoogleBucketMatch = GoogleBucketPattern.matcher(respBody);
      Matcher AzureBucketMatch = AzureBucketPattern.matcher(respBody);
      Matcher AzureTableMatch = AzureTablePattern.matcher(respBody);
      Matcher AzureQueueMatch = AzureQueuePattern.matcher(respBody);
      Matcher AzureFileMatch = AzureFilePattern.matcher(respBody);
      Matcher AzureCosmosMatch = AzureCosmosPattern.matcher(respBody);
      Matcher GcpFirebaseMatch = GcpFirebase.matcher(respBody);
      Matcher GcpFirestoreRespMatch = GcpFirestorePattern.matcher(respBody);
      Matcher ParseServerMatch = ParseServerPattern.matcher(reqRaw);
      
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
        if (validateBucket("AWS", "anonymous", BucketName) && !bucketCheckList.contains(BucketName + "-" + "AWS-Anonymous")) {
          bucketCheckList.add(BucketName + "-" + "AWS-Anonymous");
          
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
          
          // If enabled, append common bucket names to original valid bucket
          if (isBucketSubsSet) {
            try {
              appendBucketName(BucketName.replaceAll("\\.(com|net|org|edu|io)", ""), "AWS", messageInfo, S3BucketMatches);
            } catch (Exception ignore) {}
          }
        }
        
        // Perform checks from the perspecitve of any authenticated AWS user
        if (validateBucket("AWS", "anyuser", BucketName) && !bucketCheckList.contains(BucketName + "-" + "AWS-Any")) {
          bucketCheckList.add(BucketName + "-" + "AWS-Any");
        
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
        if (validateBucket("Google", "anonymous", BucketName) && !bucketCheckList.contains(BucketName + "-" + "Google-Anonymous")) {
          bucketCheckList.add(BucketName + "-" + "Google-Anonymous");
          
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
          
          // If enabled, append common bucket names to original valid bucket
          if (isBucketSubsSet) {
            try {
              appendBucketName(BucketName.replaceAll("\\.(com|net|org|edu|io)", ""), "Google", messageInfo, GoogleBucketMatches);
            } catch (Exception ignore) {}
          }
        }
        
        // Perform checks from the perspecitve of any authenticated Google user
        if (validateBucket("Google", "anyuser", BucketName) && !bucketCheckList.contains(BucketName + "-" + "Google-Any")) {
          bucketCheckList.add(BucketName + "-" + "Google-Any");
          
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
        if (validateBucket("Azure", "anonymous", BucketName) && !bucketCheckList.contains(BucketName + "-" + "Azure-Anonymous")) {
          bucketCheckList.add(BucketName + "-" + "Azure-Anonymous");
            
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
          
          // If enabled, append common bucket names to original valid bucket
          if (isBucketSubsSet) {
            try {
              appendBucketName(BucketName.replaceAll("\\.(com|net|org|edu|io)", ""), "Azure", messageInfo, AzureBucketMatches);
            } catch (Exception ignore) {}
          }
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
      
      // Create an issue noting an Azure Cosmos DB was identified in the response
      if (AzureCosmosMatch.find()) {
        List<int[]> AzureCosmosMatches = getMatches(messageInfo.getResponse(), AzureCosmosMatch.group(0).getBytes());
        IScanIssue azureCosmosIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, AzureCosmosMatches) },
          "[Anonymous Cloud] Azure Cosmos Database Identified",
          "The response body contained the following Cosmos DB: " + AzureCosmosMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the Azure bucket identification issue
        extCallbacks.addScanIssue(azureCosmosIdIssue);
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
        
        String firebaseFix = GcpFirebaseMatch.group(0).replaceAll("\\\\", "");
        if (!firebaseCheckList.contains(firebaseFix)) {
            firebaseCheckList.add(firebaseFix);
          // Check for public read/write anonymous access
          try {
            gcpFirebaseCheck(messageInfo, GcpFirebaseMatches, GcpFirebaseMatch.group(0));
          } catch (Exception ignore) {}
        
          // Check common other database names
          try {
            appendFirebaseName(GcpFirebaseMatch.group(0), messageInfo, GcpFirebaseMatches);
          } catch (Exception ignore) {}
        }
      }
      
      // Check for open Firestore access
      if (GcpFirestoreRespMatch.find()) {
        List<int[]> GcpFirestoreRespMatches = getMatches(messageInfo.getResponse(), GcpFirestoreRespMatch.group(0).getBytes());
        IScanIssue firestoreIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, GcpFirestoreRespMatches) },
          "[Anonymous Cloud] Firestore Database Identified",
          "The response body contained the following Firestore database: " + GcpFirestoreRespMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the Firebase identification issue
        extCallbacks.addScanIssue(firestoreIdIssue);
        
        String firestoreFix = GcpFirestoreRespMatch.group(0).replaceAll("\\\\", "");
        if (!firestoreCheckList.contains(firestoreFix)) {
            firestoreCheckList.add(firestoreFix);
          // Check for public read/write anonymous access
          try {
            gcpFirestoreCheck(messageInfo, null, GcpFirestoreRespMatches, GcpFirestoreRespMatch.group(0));
          } catch (Exception ignore) {}
        }
      }
      
      // Create an issue noting the use of Parse Server based on the request
      if (ParseServerMatch.find()) {
        List<int[]> ParseServerMatches = getMatches(messageInfo.getRequest(), ParseServerMatch.group(0).getBytes());
        IScanIssue parseServerIdIssue = new CustomScanIssue(
          messageInfo.getHttpService(),
          extHelpers.analyzeRequest(messageInfo).getUrl(), 
          new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, ParseServerMatches, null) },
          "[Anonymous Cloud] Parse Server Identified",
          "The response headers contained the following Parse Server application ID: " + ParseServerMatch.group(0),
          "Information",
          "Firm"
        );
        
        // Add the Parse Server identification issue
        extCallbacks.addScanIssue(parseServerIdIssue);
      }
    }
    
    return null;
  }

  // No active scanning for this but still must define it
  @Override
  public List<IScanIssue> doActiveScan(IHttpRequestResponse messageInfo, IScannerInsertionPoint insertionPoint) {
    // Only process requests if the URL is in scope and the domain has not been checked yet
    if (extCallbacks.isInScope(extHelpers.analyzeRequest(messageInfo).getUrl())) {
      // Proceeding checks obtained from https://gist.github.com/fransr/a155e5bd7ab11c93923ec8ce788e3368
      // Build basic request  
      Boolean isConfirmedAlready = false;
      String webDomain = extHelpers.analyzeRequest(messageInfo).getUrl().getHost();
      String webProto = extHelpers.analyzeRequest(messageInfo).getUrl().getProtocol();
      int webPort = extHelpers.analyzeRequest(messageInfo).getUrl().getPort();
      String langHeader = "Accept-Language: en-US,en;q=0.9,sv;q=0.8,zh-TW;q=0.7,zh;q=0.6,fi;q=0.5,it;q=0.4,de;q=0.3";
      String uaHeader = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36";
      String dateHeader = "Date: " + DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneOffset.UTC));
    
      if (!siteOnBucketCheckList.contains(webDomain)) {
        siteOnBucketCheckList.add(webDomain);

        // Try to create an invalid character URL
        try {
       
          // Create Burp service
          IHttpService httpService = extHelpers.buildHttpService(webDomain, webPort, webProto);
          List<String> headersInit = Arrays.asList("GET /%C0 HTTP/1.1", "Host: " + webDomain, langHeader, uaHeader);
          byte[] requestInit = extHelpers.buildHttpMessage(headersInit, new byte[0]);
        
          // Native Burp request
          IHttpRequestResponse httpReqResp = extCallbacks.makeHttpRequest(httpService, requestInit);
        
          // Get the response information
          String httpReqRespRaw = new String(httpReqResp.getResponse());
          String httpReqRespBody = httpReqRespRaw.substring(extHelpers.analyzeResponse(httpReqResp.getResponse()).getBodyOffset());
      
          // Create a pattern and matcher
          Pattern invalidCharPattern = Pattern.compile("(<Code>InvalidURI</Code>|Code: InvalidURI|NoSuchKey)", Pattern.CASE_INSENSITIVE);
          Matcher invalidCharMatch = invalidCharPattern.matcher(httpReqRespBody);
        
          // Create an issue noting the domain is hosted on an AWS S3 bucket
          if (invalidCharMatch.find()) {
            // Create a finding noting that the domain is hosted on a bucket
            List<int[]> invalidCharMatches = getMatches(httpReqResp.getResponse(), invalidCharMatch.group(0).getBytes());
            IScanIssue domainIsBucketIssue = new CustomScanIssue(
              httpReqResp.getHttpService(),
              extHelpers.analyzeRequest(httpReqResp).getUrl(), 
              new IHttpRequestResponse[] { extCallbacks.applyMarkers(httpReqResp, null, invalidCharMatches) },
              "[Anonymous Cloud] Domain Hosted on AWS S3 Bucket",
              "The domain appears to be hosted on an AWS S3 bucket based on the response: " + invalidCharMatch.group(0),
              "Information",
              "Firm"
            );
          
            // Add confirmed bucket issue
            extCallbacks.addScanIssue(domainIsBucketIssue);
            isConfirmedAlready = true;
          }
          
          if (!isConfirmedAlready) {
            // Create Burp service
            List<String> headers = Arrays.asList("POST /soap HTTP/1.1", "Host: " + webDomain, langHeader, uaHeader);
            byte[] request = extHelpers.buildHttpMessage(headers, new byte[0]);
        
            // Native Burp request
            httpReqResp = extCallbacks.makeHttpRequest(httpService, request);
        
            // Get the response information
            httpReqRespRaw = new String(httpReqResp.getResponse());
            httpReqRespBody = httpReqRespRaw.substring(extHelpers.analyzeResponse(httpReqResp.getResponse()).getBodyOffset());
      
            // Create a pattern and matcher
            Pattern soapPattern = Pattern.compile("(>Missing SOAPAction header<)", Pattern.CASE_INSENSITIVE);
            Matcher soapMatch = soapPattern.matcher(httpReqRespBody);
        
            // Create an issue noting the domain is hosted on an AWS S3 bucket
            if (soapMatch.find()) {
              // Create a finding noting that the domain is hosted on a bucket
              List<int[]> soapMatches = getMatches(httpReqResp.getResponse(), soapMatch.group(0).getBytes());
              IScanIssue domainIsBucketIssue = new CustomScanIssue(
                httpReqResp.getHttpService(),
                extHelpers.analyzeRequest(httpReqResp).getUrl(), 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(httpReqResp, null, soapMatches) },
                "[Anonymous Cloud] Domain Hosted on AWS S3 Bucket",
                "The domain appears to be hosted on an AWS S3 bucket based on the response: " + soapMatch.group(0),
                "Information",
                "Firm"
              );
            
              // Add confirmed bucket issue
              extCallbacks.addScanIssue(domainIsBucketIssue);
              isConfirmedAlready = true;
            }
          }
        
          if (!isConfirmedAlready) {
            // Create Burp service
            List<String> headers = Arrays.asList("POSTX /doesnotexist HTTP/1.1", "Host: " + webDomain, langHeader, uaHeader);
            byte[] request = extHelpers.buildHttpMessage(headers, new byte[0]);
        
            // Native Burp request
            httpReqResp = extCallbacks.makeHttpRequest(httpService, request);
        
            // Get the response information
            httpReqRespRaw = new String(httpReqResp.getResponse());
            httpReqRespBody = httpReqRespRaw.substring(extHelpers.analyzeResponse(httpReqResp.getResponse()).getBodyOffset());
      
            // Create a pattern and matcher
            Pattern methodPattern = Pattern.compile("(>Missing SOAPAction header<)", Pattern.CASE_INSENSITIVE);
            Matcher methodMatch = methodPattern.matcher(httpReqRespBody);
        
            // Create an issue noting the domain is hosted on an AWS S3 bucket
            if (methodMatch.find()) {
              // Create a finding noting that the domain is hosted on a bucket
              List<int[]> methodMatches = getMatches(httpReqResp.getResponse(), methodMatch.group(0).getBytes());
              IScanIssue domainIsBucketIssue = new CustomScanIssue(
                httpReqResp.getHttpService(),
                extHelpers.analyzeRequest(httpReqResp).getUrl(), 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(httpReqResp, null, methodMatches) },
                "[Anonymous Cloud] Domain Hosted on AWS S3 Bucket",
                "The domain appears to be hosted on an AWS S3 bucket based on the response: " + methodMatch.group(0),
                "Information",
                "Firm"
              );
            
              // Add confirmed bucket issue
              extCallbacks.addScanIssue(domainIsBucketIssue);
              isConfirmedAlready = true;
            }
          }
        
          if (!isConfirmedAlready && isAwsAuthSet) {
            // Create Burp service
            List<String> headers = Arrays.asList("POST /doesnotexist?123 HTTP/1.1", "Host: " + webDomain, "Authorization: AWS " + awsAccessKey + ":x", dateHeader, langHeader, uaHeader);
            byte[] request = extHelpers.buildHttpMessage(headers, new byte[0]);
        
            // Native Burp request
            httpReqResp = extCallbacks.makeHttpRequest(httpService, request);
        
            // Get the response information
            httpReqRespRaw = new String(httpReqResp.getResponse());
            httpReqRespBody = httpReqRespRaw.substring(extHelpers.analyzeResponse(httpReqResp.getResponse()).getBodyOffset());
      
            // Create a pattern and matcher
            Pattern postSignPattern = Pattern.compile("(</StringToSign>)", Pattern.CASE_INSENSITIVE);
            Matcher postSignMatch = postSignPattern.matcher(httpReqRespBody);
        
            // Create an issue noting the domain is hosted on an AWS S3 bucket
            if (postSignMatch.find()) {
              // Create a finding noting that the domain is hosted on a bucket
              List<int[]> postSignMatches = getMatches(httpReqResp.getResponse(), postSignMatch.group(0).getBytes());
              IScanIssue domainIsBucketIssue = new CustomScanIssue(
                httpReqResp.getHttpService(),
                extHelpers.analyzeRequest(httpReqResp).getUrl(), 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(httpReqResp, null, postSignMatches) },
                "[Anonymous Cloud] Domain Hosted on AWS S3 Bucket",
                "The domain appears to be hosted on an AWS S3 bucket based on the response: " + postSignMatch.group(0),
                "Information",
                "Firm"
              );
            
              // Add confirmed bucket issue
              extCallbacks.addScanIssue(domainIsBucketIssue);
              isConfirmedAlready = true;
            }
          }
        
          if (!isConfirmedAlready && isAwsAuthSet) {
            // Create Burp service
            List<String> headers = Arrays.asList("GET /doesnotexist?AWSAccessKeyId=" + awsAccessKey + "&Expires=1603060100&Signature=x HTTP/1.1", "Host: " + webDomain, dateHeader, langHeader, uaHeader);
            byte[] request = extHelpers.buildHttpMessage(headers, new byte[0]);
        
            // Native Burp request
            httpReqResp = extCallbacks.makeHttpRequest(httpService, request);
        
            // Get the response information
            httpReqRespRaw = new String(httpReqResp.getResponse());
            httpReqRespBody = httpReqRespRaw.substring(extHelpers.analyzeResponse(httpReqResp.getResponse()).getBodyOffset());
      
            // Create a pattern and matcher
            Pattern getSignPattern = Pattern.compile("(</StringToSign>)", Pattern.CASE_INSENSITIVE);
            Matcher getSignMatch = getSignPattern.matcher(httpReqRespBody);
        
            // Create an issue noting the domain is hosted on an AWS S3 bucket
            if (getSignMatch.find()) {
              // Create a finding noting that the domain is hosted on a bucket
              List<int[]> getSignMatches = getMatches(httpReqResp.getResponse(), getSignMatch.group(0).getBytes());
              IScanIssue domainIsBucketIssue = new CustomScanIssue(
                httpReqResp.getHttpService(),
                extHelpers.analyzeRequest(httpReqResp).getUrl(), 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(httpReqResp, null, getSignMatches) },
                "[Anonymous Cloud] Domain Hosted on AWS S3 Bucket",
                "The domain appears to be hosted on an AWS S3 bucket based on the response: " + getSignMatch.group(0),
                "Information",
                "Firm"
              );
            
              // Add confirmed bucket issue
              extCallbacks.addScanIssue(domainIsBucketIssue);
              isConfirmedAlready = true;
            }
          }
        
          if (!isConfirmedAlready && isAwsAuthSet) {
            // Create Burp service
            List<String> headers = Arrays.asList("PUT /doesnotexist?AWSAccessKeyId=" + awsAccessKey + "&Expires=1603060100&Signature=x HTTP/1.1", "Host: " + webDomain, dateHeader, langHeader, uaHeader);
            byte[] request = extHelpers.buildHttpMessage(headers, new byte[0]);
        
            // Native Burp request
            httpReqResp = extCallbacks.makeHttpRequest(httpService, request);
        
            // Get the response information
            httpReqRespRaw = new String(httpReqResp.getResponse());
            httpReqRespBody = httpReqRespRaw.substring(extHelpers.analyzeResponse(httpReqResp.getResponse()).getBodyOffset());
      
            // Create a pattern and matcher
            Pattern putSignPattern = Pattern.compile("(</StringToSign>)", Pattern.CASE_INSENSITIVE);
            Matcher putSignMatch = putSignPattern.matcher(httpReqRespBody);
        
            // Create an issue noting the domain is hosted on an AWS S3 bucket
            if (putSignMatch.find()) {
              // Create a finding noting that the domain is hosted on a bucket
              List<int[]> putSignMatches = getMatches(httpReqResp.getResponse(), putSignMatch.group(0).getBytes());
              IScanIssue domainIsBucketIssue = new CustomScanIssue(
                httpReqResp.getHttpService(),
                extHelpers.analyzeRequest(httpReqResp).getUrl(), 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(httpReqResp, null, putSignMatches) },
                "[Anonymous Cloud] Domain Hosted on AWS S3 Bucket",
                "The domain appears to be hosted on an AWS S3 bucket based on the response: " + putSignMatch.group(0),
                "Information",
                "Firm"
              );
            
              // Add confirmed bucket issue
              extCallbacks.addScanIssue(domainIsBucketIssue);
              isConfirmedAlready = true;
            }
          }
        
          if (!isConfirmedAlready && isAwsAuthSet) {
            // Create Burp service
            List<String> headers = Arrays.asList("POST /doesnotexist?987 HTTP/1.1", "Host: " + webDomain, "Authorization: AWS " + awsAccessKey + ":x", dateHeader, langHeader, uaHeader);
            byte[] request = extHelpers.buildHttpMessage(headers, extCallbacks.getHelpers().stringToBytes("a=b"));
        
            // Native Burp request
            httpReqResp = extCallbacks.makeHttpRequest(httpService, request);
        
            // Get the response information
            httpReqRespRaw = new String(httpReqResp.getResponse());
            httpReqRespBody = httpReqRespRaw.substring(extHelpers.analyzeResponse(httpReqResp.getResponse()).getBodyOffset());
      
            // Create a pattern and matcher
            Pattern multipartSignPattern = Pattern.compile("(</StringToSign>)", Pattern.CASE_INSENSITIVE);
            Matcher multipartSignMatch = multipartSignPattern.matcher(httpReqRespBody);
        
            // Create an issue noting the domain is hosted on an AWS S3 bucket
            if (multipartSignMatch.find()) {
              // Create a finding noting that the domain is hosted on a bucket
              List<int[]> multipartSignMatches = getMatches(httpReqResp.getResponse(), multipartSignMatch.group(0).getBytes());
              IScanIssue domainIsBucketIssue = new CustomScanIssue(
                httpReqResp.getHttpService(),
                extHelpers.analyzeRequest(httpReqResp).getUrl(), 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(httpReqResp, null, multipartSignMatches) },
                "[Anonymous Cloud] Domain Hosted on AWS S3 Bucket",
                "The domain appears to be hosted on an AWS S3 bucket based on the response: " + multipartSignMatch.group(0),
                "Information",
                "Firm"
              );
            
              // Add confirmed bucket issue
              extCallbacks.addScanIssue(domainIsBucketIssue);
              isConfirmedAlready = true;
            }
          }
        
          if (!isConfirmedAlready && isAwsAuthSet) {
            // Create Burp service
            List<String> headers = Arrays.asList("GET /doesnotexist?456 HTTP/1.1", "Host: " + webDomain, "Authorization: AWS4-HMAC-SHA256 Credential=" + awsAccessKey + "/20180101/ap-south-1/s3/aws4_request,SignedHeaders=date;host;x-amz-acl;x-amz-content-sha256;x-amz-date,Signature=x", dateHeader, "x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD", langHeader, uaHeader);
            byte[] request = extHelpers.buildHttpMessage(headers, new byte[0]);
        
            // Native Burp request
            httpReqResp = extCallbacks.makeHttpRequest(httpService, request);
        
            // Get the response information
            httpReqRespRaw = new String(httpReqResp.getResponse());
            httpReqRespBody = httpReqRespRaw.substring(extHelpers.analyzeResponse(httpReqResp.getResponse()).getBodyOffset());
      
            // Create a pattern and matcher
            Pattern streamingSignPattern = Pattern.compile("(<CanonicalRequest>)", Pattern.CASE_INSENSITIVE);
            Matcher streamingSignMatch = streamingSignPattern.matcher(httpReqRespBody);
        
            // Create an issue noting the domain is hosted on an AWS S3 bucket
            if (streamingSignMatch.find()) {
              // Create a finding noting that the domain is hosted on a bucket
              List<int[]> streamingSignMatches = getMatches(httpReqResp.getResponse(), streamingSignMatch.group(0).getBytes());
              IScanIssue domainIsBucketIssue = new CustomScanIssue(
                httpReqResp.getHttpService(),
                extHelpers.analyzeRequest(httpReqResp).getUrl(), 
                new IHttpRequestResponse[] { extCallbacks.applyMarkers(httpReqResp, null, streamingSignMatches) },
                "[Anonymous Cloud] Domain Hosted on AWS S3 Bucket",
                "The domain appears to be hosted on an AWS S3 bucket based on the response: " + streamingSignMatch.group(0),
                "Information",
                "Firm"
              );
            
              // Add confirmed bucket issue
              extCallbacks.addScanIssue(domainIsBucketIssue);
              isConfirmedAlready = true;
            }
          }
        } catch (Exception ignore) {}
      }
    }
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
    BucketName = BucketName.replaceAll("\\\\", "");
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
  
  // Append bucket names to validated bucket
  private void appendBucketName(String BucketName, String BucketType, IHttpRequestResponse messageInfo, List<int[]>BucketMatches) {
    try {
              
      // If provided with a file, use it, otherwise use default
      if (bucketFileList.exists() && bucketFileList.length() > 0) {

        BufferedReader rd = new BufferedReader(new FileReader(bucketFileList));
        String line = null;
      
        // Loop through each line
        while((line = rd.readLine()) != null) {
          // Add to bucket list if unique
          if (!bucketList.contains(BucketName + line) && !line.equals(BucketName)) {
            bucketList.add(BucketName + line);
          }
        }
        
        // Loop through the list of buckets to test
        for (int i = 0; i < bucketList.size(); i++) {
            
          // Perform anonymous checks
          if (validateBucket(BucketType, "anonymous", bucketList.get(i).toString())) {
          
            // Create a finding noting that the bucket is valid
            IScanIssue bucketConfirmIssue = new CustomScanIssue(
              messageInfo.getHttpService(),
              extHelpers.analyzeRequest(messageInfo).getUrl(), 
              new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, BucketMatches) },
              "[Anonymous Cloud] " + BucketType + " Bucket Exists",
              "The following bucket was confirmed to be valid: " + bucketList.get(i).toString(),
              "Low",
              "Certain"
            );
          
            // Add confirmed bucket issue
            extCallbacks.addScanIssue(bucketConfirmIssue);
          
            // Check for public read bucket anonymous access
            try {
              publicReadCheck(BucketType, messageInfo, BucketMatches, bucketList.get(i).toString());
            } catch (Exception ignore) {}
            
            // Perform other read/write checks as long as it isn't Azure
            if (!BucketType.contains("Azure")) {
              // Check for public write bucket anonymous access
              try {
                publicWriteCheck(BucketType, messageInfo, BucketMatches, bucketList.get(i).toString());
              } catch (Exception ignore) {}
            
              // Check for any authenticated AWS user read bucket access
              try {
                anyAuthReadCheck(BucketType, messageInfo, BucketMatches, bucketList.get(i).toString());
              } catch (Exception ignore) {}
          
              // Check for any authenticated AWS user write bucket access
              try {
                anyAuthWriteCheck(BucketType, messageInfo, BucketMatches, bucketList.get(i).toString());
              } catch (Exception ignore) {}
            }
          }
        }
      }
    } catch (Exception ignore) {}
  }
  
    // Append bucket names to validated bucket
  private void appendFirebaseName(String firebaseDb, IHttpRequestResponse messageInfo, List<int[]>FirebaseMatches) {
    String FirebaseName = firebaseDb.replaceAll("\\.firebaseio\\.com.*", "");
      
    try {
              
      // If provided with a file, use it, otherwise use default
      if (bucketFileList.exists() && bucketFileList.length() > 0) {

        BufferedReader rd = new BufferedReader(new FileReader(bucketFileList));
        String line = null;
      
        // Loop through each line
        while((line = rd.readLine()) != null) {
          // Add to bucket list if unique
          if (!firebaseList.contains(FirebaseName + line) && !line.equals(FirebaseName) && !line.contains(".")) {
            firebaseList.add(FirebaseName + line + ".firebaseio.com");
          }
        }
        
        // Loop through the list of buckets to test
        for (int i = 0; i < firebaseList.size(); i++) {
          gcpFirebaseCheck(messageInfo, FirebaseMatches, firebaseList.get(i).toString());  
        }
      }
    } catch (Exception ignore) {}
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
    firebaseDb = firebaseDb.replaceAll("\\\\", "");
    HttpGet readReq = new HttpGet("https://" + firebaseDb + "/.json");

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
          
          // Add public read firebase db access issue
          extCallbacks.addScanIssue(publicReadIssue);
        } else if (readRespHeaders.contains("401 Unauthorized") || readRespHeaders.contains("402 Payment")) {
          // Create a finding noting that the Firebase DB is valid
          IScanIssue firebaseConfirmIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(), 
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, null, matches) },
            "[Anonymous Cloud] Firebase Database Exists",
            "The following Firebase database was confirmed to be valid: " + firebaseDb,
            "Low",
            "Certain"
          );
          
          // Add valid firebase db access issue
          extCallbacks.addScanIssue(firebaseConfirmIssue);
        }
      } catch (Exception ignore) { }
    
    // Create a client to check Google for the Firebase DB
    String firebaseItem = "Burp-AnonymousCloud-" + genRandStr();
    String firebaseContent = "Burp-AnonymousCloud Extension Public Write Test!";
    HttpClient writeClient = HttpClientBuilder.create().build();
    HttpPost writeReq = new HttpPost("https://" + firebaseDb + "/.json");

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
  
  // Perform anonymous public read access check for a discovered Firestore DB
  private void gcpFirestoreCheck(IHttpRequestResponse messageInfo, List<int[]>reqMatches, List<int[]>respMatches, String firebaseDb) {
      
    // First validate we can check
    firebaseDb = firebaseDb.replaceAll("\\\\", "");
    Pattern GcpFirestoreFullPattern = Pattern.compile("(firestore\\.googleapis\\.com\\/v1\\/projects\\/[\\w.-]+\\/databases\\/\\(default\\)\\/documents\\/[\\w.-~]+)", Pattern.CASE_INSENSITIVE);
    Matcher GcpFirestoreFullMatch = GcpFirestoreFullPattern.matcher(firebaseDb);
    
    if (GcpFirestoreFullMatch.find()) {
      // Create a client to check Google for the Firestore DB
      HttpClient readClient = HttpClientBuilder.create().build();
      HttpGet readReq = new HttpGet("https://" + GcpFirestoreFullMatch.group(0));

      // Connect to GCP services for Firestore DB access
      try {
        HttpResponse readResp = readClient.execute(readReq);
        String readRespHeaders = readResp.getStatusLine().toString();

        // If the status is 200, it is public, otherwise doesn't exist or requires auth
        if (readRespHeaders.contains("200 OK")) {
          // Create public access issue
          IScanIssue publicReadIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(),
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, reqMatches, respMatches) },
            "[Anonymous Cloud] Publicly Accessible Firestore Database",
            "The following Firestore database is publicly readable: " + GcpFirestoreFullMatch.group(0),
            "Medium",
            "Certain"
          );
          
          // Add public read Firestore db access issue
          extCallbacks.addScanIssue(publicReadIssue);
        } else if (readRespHeaders.contains("403 Forbidden")) {
          // Create a finding noting that the Firestore DB is valid
          IScanIssue firestoreConfirmIssue = new CustomScanIssue(
            messageInfo.getHttpService(),
            extHelpers.analyzeRequest(messageInfo).getUrl(), 
            new IHttpRequestResponse[] { extCallbacks.applyMarkers(messageInfo, reqMatches, respMatches) },
            "[Anonymous Cloud] Firestore Database Exists",
            "The following Firestore database was confirmed to be valid: " + GcpFirestoreFullMatch.group(0),
            "Low",
            "Certain"
          );
          
          // Add valid firestore db access issue
          extCallbacks.addScanIssue(firestoreConfirmIssue);
        }
      } catch (Exception ignore) { }
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