import ballerina/crypto;
import ballerina/http;
import ballerina/time;
//import ballerina/url as url;

import choreo/mediation;
import ballerina/log;

// A mediation policy package consists of 1-3 functions, each corresponding to one of the 3 possible request/response
// flows:
// - In-flow function is applied to a request coming in to a resource in the proxy
// - Out-flow function is applied to the response received from the upstream server before forwarding it to the client
// - Fault-flow function is applied if an error occurs in any of the above 2 flows and the control flow is handed over
//   to the error handling flow
//
// A policy can contain any combination of the above 3 flows. Therefore one can get rid of up to any 2 of the following
// functions. The function names are irrelevant. Therefore one can name them as they see fit.

// The first 2 parameters are required. After the first 2 parameters, one can add arbitrary number of parameters of
// the following types: int, string, float, boolean, decimal. However, all policy functions should have exactly the same
// number and types of these arbitrary parameters.
@mediation:RequestFlow
public function policyNameIn(mediation:Context ctx, http:Request req,string aws_accesskey, string aws_accesssecret, string aws_region, string aws_service, string aws_host)
                                returns http:Response|false|error|() {
   

    // Set the current date in AWS format
    time:Utc currentDateTime = time:utcNow();
    time:Civil civilDateTime = time:utcToCivil(currentDateTime);

    int hour = civilDateTime.hour is int ? civilDateTime.hour : 0;
    int minute = civilDateTime.minute is int ? civilDateTime.minute : 0;
    int second = civilDateTime.second is decimal ? check <int> civilDateTime.second : 0;

    // Manually format amzDate and dateStamp
    string amzDate = civilDateTime.year.toString() + pad(civilDateTime.month) + pad(civilDateTime.day) + "T" +
                     pad(hour) + pad(minute) + pad(second) + "Z";
    string dateStamp = civilDateTime.year.toString() + pad(civilDateTime.month) + pad(civilDateTime.day);

   
    // Define AWS signing scope
    string credentialScope = string `${dateStamp}/${aws_region}/${aws_service}/aws4_request`;

    // Prepare canonical request elements
    string canonicalURI = "/";
    string canonicalQueryString = ""; // No query parameters
    string canonicalHeaders = "host:" + aws_host + "\n" + "x-amz-date:" + amzDate + "\n";
    string signedHeaders = "host;x-amz-date";

     // Generate SHA-256 hash for an empty payload
    byte[] emptyPayload = [];
    byte[] payloadHashBytes = crypto:hashSha256(emptyPayload);
    string payloadHash = payloadHashBytes.toBase16().toLowerAscii();


     // Create the canonical request
     string canonicalRequest = 
                            string:concat("GET\n", canonicalURI, "\n", canonicalQueryString, "\n", canonicalHeaders, "\n", signedHeaders, "\n", payloadHash);
                            
    log:printInfo("Canonical Request:", canonicalRequest=canonicalRequest);
    
    // Create the string to sign
    string algorithm = "AWS4-HMAC-SHA256";
    string stringToSign = string `${algorithm}
${amzDate}
${credentialScope}
${crypto:hashSha256(canonicalRequest.toBytes()).toBase16().toLowerAscii()}`;

    // Derive the signing key, logging each intermediate key for detailed debugging
    byte[] kDate = check sign(("AWS4" + aws_accesssecret).toBytes(), dateStamp);
    log:printInfo("kDate:", kDate=kDate.toBase16().toLowerAscii());

    byte[] kRegion = check sign(kDate, aws_region);
    log:printInfo("kRegion:", kRegion=kRegion.toBase16().toLowerAscii());

    byte[] kService = check sign(kRegion, aws_service);
    log:printInfo("kService:",kService= kService.toBase16().toLowerAscii());

    byte[] signingKey = check sign(kService, "aws4_request");
    log:printInfo("Signing Key:", signingKey=signingKey.toBase16().toLowerAscii());

    // Calculate the final signature
    byte[] signatureBytes = check sign(signingKey, stringToSign);
    string signature = signatureBytes.toBase16().toLowerAscii();

    // Construct the Authorization header
    string authorizationHeader = string `${algorithm} Credential=${aws_accesskey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    // Set headers to the request
    req.setHeader("X-Amz-Date", amzDate);
    req.setHeader("Authorization", authorizationHeader);

    return ();

}

// Helper function to pad single-digit numbers with a leading zero
function pad(int num) returns string {
    return num < 10 ? "0" + num.toString() : num.toString();
}

// Helper function to perform HMAC SHA256 signing
function sign(byte[] key, string data) returns byte[]|error {
    return check crypto:hmacSha256(data.toBytes(),key);
}
