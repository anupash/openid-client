#!/bin/bash

# Store our credentials in our home directory with a file called .<script name>
my_creds=~/.`basename $0`

### Gmail API
client_id='xxxxxxxxxxxxxxxxx'
client_secret='xxxxxxxxxxxxxxxxxxxxx' # not really a secret

csrf=`openssl rand -base64 1024 | sha256sum  | cut -d' ' -f 1`

### Declaring token variables
access_token=''
refresh_token=''
id_token=''
expires_in=''
expires_at=''

if [ -s $my_creds ]; then
  # Use the token stored from previous rung
  . $my_creds
  time_now=`date +%s`
else
  scope='https://www.googleapis.com/auth/admin.directory.user.readonly'
  # Form the request URL
  # http://goo.gl/U0uKEb
  # auth_url="https://accounts.google.com/o/oauth2/auth?client_id=$client_id&scope=$scope&response_type=code&redirect_uri=urn:ietf:wg:oauth:2.0:oob"

  auth_url=`printf "%s%s%s%s%s%s" "https://accounts.google.com/o/oauth2/v2/auth?"\
  			"client_id=$client_id&"\
  			"response_type=code&scope=openid%20email%20profile&"\
  			"redirect_uri=urn:ietf:wg:oauth:2.0:oob&"\
  			"state=security_token%3D"$csrf"%26url%3Durn:ietf:wg:oauth:2.0:oob&"`
  			
  echo "Please go to:"
  echo
  echo "$auth_url"
  echo
  echo "after accepting, enter the code you are given:"
  read auth_code

  # swap authorization code for access and refresh tokens
  # http://goo.gl/Mu9E5J
  auth_result=$(curl -s https://accounts.google.com/o/oauth2/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d code=$auth_code \
    -d client_id=$client_id \
    -d client_secret=$client_secret \
    -d redirect_uri=urn:ietf:wg:oauth:2.0:oob \
    -d grant_type=authorization_code)

  echo "Response from the openid authentication request:"
  echo
  echo $auth_result
  echo
  echo "Parsing the response "


  access_token=$(echo -e "$auth_result" | \
                 ggrep -Po '"access_token" *: *.*?[^\\]",' | \
                 awk -F'"' '{ print $4 }')
  refresh_token=$(echo -e "$auth_result" | \
                  ggrep -Po '"refresh_token" *: *.*?[^\\]",*' | \
                  awk -F'"' '{ print $4 }')
  id_token=$(echo -e "$auth_result" | \
                  ggrep -Po '"id_token" *: *.*?[^\\]",*' | \
                  awk -F'"' '{ print $4 }')                     
  expires_in=$(echo -e "$auth_result" | \
               ggrep -Po '"expires_in" *: *.*' | \
               awk -F' ' '{ print $3 }' | awk -F',' '{ print $1}')
  time_now=`date +%s`
  expires_at=$((time_now + expires_in - 60))
  echo -e "access_token=$access_token\nrefresh_token=$refresh_token\nexpires_at=$expires_at\nid_token=$id_token" > $my_creds
  echo -e $refresh_result
fi

# if our access token is expired, use the refresh token to get a new one
# http://goo.gl/71rN6V
if [ $time_now -gt $expires_at ]; then
  echo "Refreshing Token"
  refresh_result=$(curl -s https://accounts.google.com/o/oauth2/token \
   -H "Content-Type: application/x-www-form-urlencoded" \
   -d refresh_token=$refresh_token \
   -d client_id=$client_id \
   -d client_secret=$client_secret \
   -d grant_type=refresh_token)
  echo "$refresh_result"
  access_token=$(echo -e "$refresh_result" | \
                 ggrep -Po '"access_token" *: *.*?[^\\]",' | \
                 awk -F'"' '{ print $4 }')
  expires_in=$(echo -e "$refresh_result" | \
               ggrep -Po '"expires_in" *: *.*' | \
               awk -F' ' '{ print $3 }' | awk -F',' '{ print $1 }')
  id_token=$(echo -e "$refresh_result" | \
                  ggrep -Po '"id_token" *: *.*?[^\\]",*' | \
                  awk -F'"' '{ print $4 }')                     
  time_now=`date +%s`
  expires_at=$(($time_now + $expires_in - 60))
  echo -e "access_token=$access_token\nrefresh_token=$refresh_token\nexpires_at=$expires_at\nid_token=$id_token" > $my_creds
  echo -e "Refresh Token Response:\n\taccess_token=$access_token\n\trefresh_token=$refresh_token\n\texpires_at=$expires_at\n\tid_token=$id_token"
fi

echo -e "Stored Cookies:\n\taccess_token=$access_token\n\trefresh_token=$refresh_token\n\texpires_at=$expires_at\n\tid_token=$id_token"

## Parsing id_token
echo "------------------------Parsing id_token-------------------------"
id_header=''
id_body=''
id_sig='' 

IFS='.' read -ra id_array <<< "$id_token"

id_header=`echo -e ${id_array[0]}`
id_body=`echo -e ${id_array[1]}`
id_sig=`echo -e ${id_array[2]}`

id_payload=$id_header"."$id_body

echo -e $id_payload > /tmp/data
echo -e $id_sig > /tmp/sig

## Fix the padding for base64 decoding without errors
id_header_len=`expr 4 - ${#id_header} % 4`
id_body_len=`expr 4 - ${#id_body} % 4`
id_sig_len=`expr 4 - ${#id_sig} % 4`

for ((i=1; i <= $id_header_len;i++))
do
  id_header=$id_header'='
done
for ((i=1; i <= $id_body_len;i++))
do
  id_body=$id_body'='
done
for ((i=1; i <= $id_sig_len;i++))
do
  id_sig=$id_sig'='
done

## Base64 decoding of header and body fields from the id_token
id_header=`openssl base64 -d -A <<< "$id_header"`
id_body=`openssl base64 -d -A <<< "$id_body"`
id_sig=`openssl base64 -d -A <<< "$id_sig"`

echo "Header = "$id_header
echo "Body = "$id_body
echo "Extra = "$id_extra

aud=`echo -e "$id_body" | \
     jq .aud | \
     sed -e 's/^"//'  -e 's/"$//'` 
iss=`echo -e "$id_body" | \
     jq .iss | \
     sed -e 's/^"//'  -e 's/"$//'`

if [ "$aud" != "$client_id" ] || [ "$iss" != 'accounts.google.com' ];
then
  echo "aud field in id_token : $aud not equal to client_id : $client_id, iss : $iss"
  exit 1  
fi

### Fetching the discovery doc to get the JSON Web Key Signing Url
discovery_doc=$(curl https://accounts.google.com/.well-known/openid-configuration)
jwks_uri=`echo -e $discovery_doc | \
          jq .jwks_uri | \
          sed -e 's/^"//'  -e 's/"$//'`

### Fetching the JSON Web Key used to sign the id_token
cert=$(curl $jwks_uri)
kid=`echo -e $id_header | \
          jq .kid | \
          sed -e 's/^"//'  -e 's/"$//'`
alg=`echo -e $id_header | \
          jq .alg | \
          sed -e 's/^"//'  -e 's/"$//'`

### Fetching the key corresponding to the kid received in the id_token header
key=`echo -e $cert | \
     jq --arg keyid "$kid" '.keys[] | select(.kid == $keyid)'`
echo "Key: "$key

### Parse the key and get the key parameters
key_alg=`echo -e $key | \
          jq .alg | \
          sed -e 's/^"//'  -e 's/"$//'`
key_mod=`echo -e $key | \
          jq .n | \
          sed -e 's/^"//'  -e 's/"$//'`
key_exp=`echo -e $key | \
          jq .e | \
          sed -e 's/^"//'  -e 's/"$//'`

key_mod_len=`expr 4 -  ${#key_mod} % 4`
key_exp_len=`expr 4 - ${#key_exp} % 4`

#for ((i=1; i <= $key_mod_len;i++))
#do
#  key_mod=$key_mod'='
#done
#for ((i=1; i <= $key_exp_len;i++))
#do
#  key_exp=$key_exp'='
#done

echo "Modulus : "$key_mod
echo "Exponent : "$key_exp
echo "id_token: "$id_token

javac Main.java VerifySignature.java
java Main `echo -e $id_token` `echo -e $key_mod` `echo -e $key_exp`


