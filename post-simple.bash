#!/bin/bash

mapfile -t lines < "$HOME/.awssecret"
access_key="${lines[0]}"
secret_key="${lines[1]}"

region='eu-west-1'
service='sqs'
action='ListQueues'
wsdl_version='2012-11-05'
payload="Action=$action&Version=$wsdl_version"
host="$service.$region.amazonaws.com"

x_amz_date_long=$(date -u '+%Y%m%dT%H%M%SZ')
x_amz_date_short="${x_amz_date_long/T*}"
content_type='application/x-www-form-urlencoded; charset=utf-8'


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Task 1: Create a canonical request
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http_request_method='POST'
canonical_uri='/'
canonical_query_string=''

canonical_headers="content-type:$content_type
host:$host
x-amz-date:$x_amz_date_long"

signed_headers='content-type;host;x-amz-date'

hashed_payload=$(printf "$payload" | sha256sum)
hashed_payload="${hashed_payload%% *}"

canonical_request="$http_request_method
$canonical_uri
$canonical_query_string
$canonical_headers

$signed_headers
$hashed_payload"

hashed_canonical_request=$(printf "$canonical_request" | sha256sum)
hashed_canonical_request="${hashed_canonical_request%% *}"


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Task 2: Create a string to sign
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
string_to_sign="AWS4-HMAC-SHA256
$x_amz_date_long
$x_amz_date_short/$region/$service/aws4_request
$hashed_canonical_request"


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Task 3: Calculate the signature
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
hex_secret=$(printf "AWS4$secret_key" | xxd -p -c 256)
digest=$(printf "$x_amz_date_short" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$hex_secret)
digest="${digest#* }"
digest=$(printf "$region" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$digest)
digest="${digest#* }"
digest=$(printf "$service" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$digest)
digest="${digest#* }"
digest=$(printf "aws4_request" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$digest)
signing_key="${digest#* }"

signature=$(printf "$string_to_sign" | openssl dgst -binary -hex -sha256 -mac HMAC -macopt hexkey:$signing_key)
signature="${signature#* }"


#~~~~~~~~
# Try it
#~~~~~~~~
read -r -d '' curl_params<<END
url = "http://$host"
-H "Content-Type: $content_type"
-H "X-Amz-Date: $x_amz_date_long"
-H "Host: $host"
-H "Authorization: AWS4-HMAC-SHA256 Credential=$access_key/$x_amz_date_short/$region/$service/aws4_request, SignedHeaders=$signed_headers, Signature=$signature"
-d "$payload"
END

curl -v -K - < <(printf "$curl_params")
