#!/bin/bash

aws_secret_key_file="$HOME/.awssecret"

region='eu-west-1'

x_amz_date=$(date -u '+%Y%m%dT%H%M%SZ')
date="${x_amz_date/T*}"


#~~~~~~~~~~~~~~~~~~~~
# Fetch aws keys
#~~~~~~~~~~~~~~~~~~~~
lineno=0
while read -r line; do
	(( lineno++ ))
	if (( lineno == 1 )); then
		access_key="$line"
	elif (( lineno == 2 )); then
		secret_key="$line"
	fi
done < "$aws_secret_key_file"

if (( lineno != 2 )); then
	printf '%s\n' 'AWS secret key file should only have 2 lines'
	exit 1
fi


get_wsdl_version() {
	service="$1"
	
	if [[ $service == sqs ]]; then
		version='2012-11-05'
	else
		printf '%s\n' 'WSDL version not found'
		exit 1
	fi
	printf "$version"
}


get_host() {
	service="$1"

	if [[ $service == sqs ]]; then
		host="$service.$region.amazonaws.com"
	else
		printf '%s\n' "Unable to construct host for service $service"
		exit 1
	fi

	printf "$host"
}


derive_signing_key() {
	service="$1"

	hashed_secret=$(printf "AWS4$secret_key" | xxd -p -c 256)
	hash_1=$(printf "$date" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$hashed_secret)
	hash_1="${hash_1##* }"
	hash_2=$(printf "$region" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$hash_1)
	hash_2="${hash_2##* }"
	hash_3=$(printf "$service" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$hash_2)
	hash_3="${hash_3##* }"
	hash_4=$(printf "aws4_request" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$hash_3)
	hash_4="${hash_4##* }"

	printf "$hash_4"
}


make_post_request() {
	service="$1"
	action="$2"

	http_request_method='POST'
	canonical_uri='/'
	canonical_query_string=''
	host=$(get_host "$service")
	canonical_headers="content-type:application/x-www-form-urlencoded; charset=utf-8
host:$host
x-amz-date:$x_amz_date"
	signed_headers='content-type;host;x-amz-date'

	wsdl_version=$(get_wsdl_version "$service")
	payload="Action=$action&Version=$wsdl_version"
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

	string_to_sign="AWS4-HMAC-SHA256
$x_amz_date
$date/$region/$service/aws4_request
$hashed_canonical_request"

	signing_key=$(derive_signing_key $service)
	
	signature=$(printf "$string_to_sign" | openssl dgst -binary -hex -sha256 -mac HMAC -macopt hexkey:$signing_key)
	signature="${signature##* }"

	curl -H "Authorization: AWS4-HMAC-SHA256 Credential=$access_key/$date/$region/$service/aws4_request, SignedHeaders=$signed_headers, Signature=$signature" -H "$canonical_headers" -d "$payload" -v "https://$host"
}


make_post_request "$1" "$2"
