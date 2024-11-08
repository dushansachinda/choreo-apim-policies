import ballerina/crypto;
import ballerina/time;
import ballerina/log;

public function main() returns error? {
    string aws_accesskey = "xxxx";
    string aws_accesssecret = "xx";
    string aws_region = "us-east-1";
    string aws_service = "lambda";
    string aws_host = "wuxxcvrcq7kxwlx4xtxpl5f6py0obiyf.lambda-url.us-east-1.on.aws";

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
    //string canonicalHeaders = string `host:${aws_host}\nx-amz-date:${amzDate}\n`;
    string canonicalHeaders = "host:" + aws_host + "\n" + "x-amz-date:" + amzDate + "\n";
    string signedHeaders = "host;x-amz-date";

    // Generate SHA-256 hash for an empty payload
    byte[] emptyPayload = [];
    byte[] payloadHashBytes = crypto:hashSha256(emptyPayload);
    string payloadHash = payloadHashBytes.toBase16().toLowerAscii();

    // Create the canonical request
     // Create the canonical request
     string canonicalRequest = //"GET\n" + canonicalURI + "\n" + canonicalQueryString + "\n" +
                            //canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash;
                            string:concat("GET\n", canonicalURI, "\n", canonicalQueryString, "\n", canonicalHeaders, "\n", signedHeaders, "\n", payloadHash);
                            
    log:printInfo("Canonical Request:", canonicalRequest=canonicalRequest);
    
    // Create the string to sign
    string algorithm = "AWS4-HMAC-SHA256";
    string stringToSign = string `${algorithm}
${amzDate}
${credentialScope}
${crypto:hashSha256(canonicalRequest.toBytes()).toBase16().toLowerAscii()}`;

    log:printInfo("String to Sign:", stringToSign=stringToSign);

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

    // Logging output to verify
    log:printInfo("Authorization Header", authorizationHeader=authorizationHeader);
    log:printInfo("Amz Date", amzDate=amzDate);

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

