#!/bin/bash

my_vars() {
	mapfile -t lines < "$HOME/.awssecret"
	access_key="${lines[0]}"
	secret_key="${lines[1]}"
	
	region='eu-west-1'
	service='sqs'
	action='ListQueues'
	wsdl_version='2012-11-05'
	payload="Action=$action&Version=$wsdl_version"
	
	host="$service.$region.amazonaws.com"
	date_name='x-amz-date'
	x_amz_date_long=$(date -u '+%Y%m%dT%H%M%SZ')
	x_amz_date_short="${x_amz_date_long/T*}"
	date="$x_amz_date_long"

	canonical_headers="content-type:application/x-www-form-urlencoded; charset=utf8
host:$host
${date_name,,}:$date"
	echo "--- canonical_headers ---"
	echo "$canonical_headers"
	signed_headers="content-type;host;${date_name,,}"

	curl_headers="Content-Type: application/x-www-form-urlencoded; charset=utf8
X-Amz-Date: $x_amz_date_long"
}

example_vars() {
	access_key='AKIDEXAMPLE'
	secret_key='wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'

	region='us-east-1'
	service='iam'
	action='ListUsers'
	wsdl_version='2010-05-08'
	payload="Action=$action&Version=$wsdl_version"

	host="$service.amazonaws.com"
	date_name='x-amz-date'
	x_amz_date_long='20110909T233600Z'
	x_amz_date_short="${x_amz_date_long/T*}"
	date="$x_amz_date_long"

	canonical_headers="content-type:application/x-www-form-urlencoded; charset=utf8
host:$host
${date_name,,}:$date"
	echo "--- canonical_headers ---"
	echo "$canonical_headers"
	signed_headers="content-type;host;${date_name,,}"
	#signed_headers="content-type;${date_name,,};host"
}

test_suite_post_form() {
	access_key='AKIDEXAMPLE'
	secret_key='wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'

	region='us-east-1'
	service='host'
	payload='foo=bar'

	host="host.foo.com"
	date_name='Date'
	x_amz_date_long='20110909T233600Z'
	x_amz_date_short='20110909'
	date='Mon, 09 Sep 2011 23:36:00 GMT'

	canonical_headers="content-type:application/x-www-form-urlencoded; charset=utf8
${date_name,,}:$date
host:$host"
	echo "--- canonical_headers ---"
	echo "$canonical_headers"
	signed_headers="content-type;${date_name,,};host"
}

my_vars
#example_vars
#test_suite_post_form



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Task 1: Create a canonical request
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http_request_method='POST'
canonical_uri='/'
canonical_query_string=''

hashed_payload=$(printf "$payload" | sha256sum)
hashed_payload="${hashed_payload%% *}"

canonical_request="$http_request_method
$canonical_uri
$canonical_query_string
$canonical_headers

$signed_headers
$hashed_payload"
echo "--- canonical request ---"
echo "$canonical_request"

hashed_canonical_request=$(printf "$canonical_request" | sha256sum)
hashed_canonical_request="${hashed_canonical_request%% *}"


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Task 2: Create a string to sign
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
string_to_sign="AWS4-HMAC-SHA256
$x_amz_date_long
$x_amz_date_short/$region/$service/aws4_request
$hashed_canonical_request"
echo "--- string_to_sign ---"
echo "$string_to_sign"


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
echo "--- signature ---"
echo "$signature"


#~~~~~~~~
# Try it
#~~~~~~~~
curl -H "Authorization: AWS4-HMAC-SHA256 Credential=$access_key/$x_amz_date_short/$region/$service/aws4_request, SignedHeaders=$signed_headers, Signature=$signature" -H "$curl_headers" -d "$payload" "http://$host" -v
