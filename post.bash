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
	
	headers+=(["X-Amz-Date"]="$x_amz_date_long")
	headers+=(["Content-Type"]="application/x-www-form-urlencoded; charset=utf-8")
	headers+=(["Host"]="$host")

	headers_to_sign=("Host" "Content-Type" "X-Amz-Date")
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

	headers+=(["X-Amz-Date"]="$x_amz_date_long")
	headers+=(["Content-Type"]="application/x-www-form-urlencoded; charset=utf-8")
	headers+=(["Host"]="$host")

	headers_to_sign=("Host" "Content-Type" "X-Amz-Date")

	echo "=== Expected ==="
	echo "hashed payload: b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2"
	echo "hashed canonical request: 3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2"
	echo "signature: ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c"
	echo "=== End ==="
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

	headers+=(["Date"]="$date")
	headers+=(["Content-Type"]="application/x-www-form-urlencoded; charset=utf8")
	headers+=(["Host"]="$host")

	headers_to_sign=("Host" "Content-Type" "Date")

	echo "=== Expected ==="
	echo "hashed payload: 3ba8907e7a252327488df390ed517c45b96dead033600219bdca7107d1d3f88a"
	echo "hashed canonical request: c4115f9e54b5cecf192b1eaa23b8e88ed8dc5391bd4fde7b3fff3d9c9fe0af1f"
	echo "signature: b105eb10c6d318d2294de9d49dd8b031b55e3c3fe139f2e637da70511e9e7b71"
	echo "=== End ==="
}

declare -A headers

my_vars
#example_vars
#test_suite_post_form


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Task 1: Create a canonical request
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
http_request_method='POST'
canonical_uri='/'
canonical_query_string=''

unsorted_canonical_headers=()
for header_name in "${headers_to_sign[@]}"; do
	unsorted_canonical_headers+=("${header_name,,}:${headers[$header_name]}")
done

canonical_headers=$(printf '%s\n' "${unsorted_canonical_headers[@]}" | sort)

signed_headers=$(printf '%s\n' "${headers_to_sign[@]}" | sort)
signed_headers="${signed_headers,,}"
signed_headers=$(printf "$signed_headers" | tr '\n' ';')
signed_headers="${signed_headers%;}"

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
for header in "${!headers[@]}"; do
	new_header="\"$header: ${headers[$header]}\""
	if [[ -z $curl_headers ]]; then
		curl_headers="-H $new_header"
	else
		curl_headers="$curl_headers
-H $new_header"
	fi
done

read -r -d '' curl_params<<END
url = "http://$host"
$curl_headers
-H "Authorization: AWS4-HMAC-SHA256 Credential=$access_key/$x_amz_date_short/$region/$service/aws4_request, SignedHeaders=$signed_headers, Signature=$signature"
-d "$payload"
END

curl -K - < <(printf "$curl_params")
