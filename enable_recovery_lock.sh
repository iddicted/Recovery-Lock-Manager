#!/bin/zsh --no-rcs

# Script to set Recovery Lock on all computers in a specified Smart Group in Jamf Pro
# DESCRIPTION:
	# The script creates a Smart Group in Jamf Pro that identifies computers where Recovery Lock is not enabled.
	# It then retrieves the members of this group and sets the Recovery Lock for each computer.
	# The script uses the Jamf Pro API Clients to perform these actions.

# REQUIREMENTS: jq, curl, and a valid Jamf Pro API client with appropriate permissions
	# Preparation:
		# 1. Create a Jamf Pro API client with the necessary permissions to manage computers and groups.
			# (Mimimum permissions:
				# - Read Advanced Computer Searches
				# - Send Set Recovery Lock Command
				# - Read Smart Computer Groups
				# - View MDM command information in Jamf Pro API
				# - Read Computers, Create Smart Computer Groups)
		# 2. Replace the configuration variables below with your Jamf Pro URL, client ID, client secret, and the name of the Smart Group you want to target.
		# 3. Ensure you have jq installed for JSON parsing. (preinstallaed with macOS Sequoia (version 15) and later)
#####
# by Raphael Eckersley
# Creation Date: 2023-10-30
# Version: 2.0
#####



#### Configuration Variables ####
jamf_pro_url="JAMF_PRO_URL_HERE" # Replace with your Jamf Pro URL (e.g., "https://example.jamfcloud.com:")
client_id="CLIENT_ID_HERE" # Replace with your client ID
client_secret="CLIENT_SECRET_HERE" # Replace with your client secret
group_name="GROUP_NAME_HERE" # Name of the Smart Group to create or check (e.g., "Recovery Lock Not Enabled")
site_ID="-1" # Site ID, -1 for all sites (default)
recovery_password="Jamf123456"
#### End Configuration Variables ####


#### Functions ####
# Functions for authentication and token management
getAccessToken() {
    response=$(curl --silent --location --request POST "${jamf_pro_url}/api/oauth/token" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "client_id=${client_id}" \
        --data-urlencode "grant_type=client_credentials" \
        --data-urlencode "client_secret=${client_secret}")
    access_token=$(echo "$response" | jq -r '.access_token')
    token_expires_in=$(echo "$response" | jq -r '.expires_in')
    token_expiration_epoch=$(($current_epoch + $token_expires_in - 1))
	if [[ "$response" == *error* ]]; then
		echo "Failed to retrieve access token or expiration time."
		exit 1
	fi
	echo "Access token retrieved successfully."
	echo "Token expires in: $token_expires_in seconds"
}
checkTokenExpiration() {
    current_epoch=$(date +%s)
    if [[ token_expiration_epoch -ge current_epoch ]]
    then
        echo "Token valid until the following epoch time: " "$token_expiration_epoch"
    else
        echo "No valid token available, getting new token"
        getAccessToken
    fi
}
invalidateToken() {
    responseCode=$(curl -w "%{http_code}" -H "Authorization: Bearer ${access_token}" $jamf_pro_url/api/v1/auth/invalidate-token -X POST -s -o /dev/null)
    if [[ ${responseCode} == 204 ]]
    then
        echo "Token successfully invalidated"
        access_token=""
        token_expiration_epoch="0"
    elif [[ ${responseCode} == 401 ]]
    then
        echo "Token already invalid"
    else
        echo "An unknown error occurred invalidating the token"
    fi
}

# Function to get group info by name
get_group_info() {
	curl --silent --request GET \
		--url "$jamf_pro_url/api/v2/computer-groups/smart-groups?page=0&page-size=100&sort=id%3Aasc&filter=name==%22${group_name// /%20}%22" \
		--header "Authorization: Bearer $access_token" \
		--header 'accept: application/json' \
		--header 'content-type: application/json'
}

# Function to create a random password
generate_random_password() {
	local length=12
	local charset='A-Za-z0-9!@#$%^&*()_+'
	local password=$(cat /dev/urandom | tr -dc "$charset" | fold -w "$length" | head -n 1)
	echo "$password"
}
###### End Functions #####


#### Main Script Execution #####
# check / get access token
echo "#### Checking / retrieving access token ####"
checkTokenExpiration

# BEGIN API COMMANDS #


echo "#### Authentication successful. proceeding with API commands ####"
echo ""
# creating the needed smart group if it does not exist
# First check if the group already exists


# Check if group exists
group_exists=$(get_group_info)
#echo "DEBUG: $group_exists"

if [[ $(echo "$group_exists" | jq -r '.results | length') -gt 0 ]]; then
	group_id=$(echo "$group_exists" | jq -r '.results[0].id')
	echo "The Smart Computer Group '$group_name' with ID '$group_id' already exists. Proceeding..."
	echo ""
else
	echo "Creating smart group '$group_name'..."
	create_response=$(curl --silent --request POST \
		--url "$jamf_pro_url/api/v2/computer-groups/smart-groups" \
		--header "Authorization: Bearer $access_token" \
		--header 'accept: application/json' \
		--header 'content-type: application/json' \
		--data "{
			\"name\": \"${group_name}\",
			\"criteria\": [
				{
					\"name\": \"Recovery Lock Enabled\",
					\"value\": \"Not Enabled\",
					\"searchType\": \"is\",
					\"andOr\": \"and\"
				}
			],
			\"siteId\": \"$site_ID\"
		}")
	#echo "DEBUG (create): $create_response"
	# Check again if group exists
	group_exists=$(get_group_info)
	if [[ $(echo "$group_exists" | jq -r '.results | length') -gt 0 ]]; then
		group_id=$(echo "$group_exists" | jq -r '.results[0].id')
		echo "Successfully create the Smart Computer Group: Name: '$group_name' ID: '$group_id'. Proceeding..."
		echo ""
		
	else
		echo "Failed to create smart group '$group_name'."
		exit 1
	fi
fi

# Check if password was provided, if not generate a random one
if [[ -z "$recovery_password" ]]; then
	echo "No recovery password provided. Generating a random password..."
	recovery_password=$(generate_random_password)
	echo "Generated a random Recovery Password!"
else
	echo "Using provided Recovery Password!"
fi


# Get members of Smart Computer Group
group_members=$(curl --request GET \
	--url "$jamf_pro_url/api/v2/computer-groups/smart-group-membership/$group_id" \
	--silent \
	--header 'accept: application/json' \
	--header "Authorization: Bearer ${access_token}")

echo "DEBUG $group_members"

# extract computer IDs from the group members
computer_ids=$(echo "$group_members" | jq -r '.members[]')

# iterate through each computer ID
echo "$computer_ids" | while read -r computer_id; do
	[[ -z "$computer_id" ]] && continue
	echo "#################### Processing computer ID: $computer_id ####################"
	# get computer inventory information by computer ID
	echo "Getting management ID for computer ID: $computer_id"
	computer_inventory=$(curl -s --location --request GET "${jamf_pro_url}/api/v1/computers-inventory-detail/${computer_id}" \
	--header "accept: application/json" \
	--header "Authorization: Bearer ${access_token}")

	managementId=$(echo "$computer_inventory" | tr -d '\000-\037' | jq -r '.general.managementId')
	echo "Management ID: $managementId"

	# set recovery lock
	echo "Setting Recovery Lock for Management ID: $managementId"
	response=$(curl -s -w "%{http_code}" -o /tmp/set_recovery_lock_response.json \
	--location \
	--request POST "${jamf_pro_url}/api/v2/mdm/commands" \
	--header "Authorization: Bearer $access_token" \
	--header "Content-Type: application/json" \
	--data-raw "{
		\"clientData\": [
			{
				\"managementId\": \"${managementId}\",
				\"clientType\": \"COMPUTER\"
			}
		],
		\"commandData\": {
			\"commandType\": \"SET_RECOVERY_LOCK\",
			\"newPassword\": \"${recovery_password}\",
		}
	}")

	echo "Response code: $response"
	if [[ "$response" -eq 201 ]]; then
		echo "Recovery Lock set successfully."
	else
		echo "Failed to set Recovery Lock. Response code: $response"
		cat /tmp/set_recovery_lock_response.json
	fi
	echo "#################### Finished processing computer ID: $computer_id ####################"
	echo ""
done
# END API COMMANDS #

echo ""
checkTokenExpiration
invalidateToken
