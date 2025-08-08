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
				# - Update Smart Computer Groups
				# - Create Smart Computer Groups
				# - View MDM command information in Jamf Pro API
				# - Read Computers)
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
group_name_lock_disabled="GROUP_NAME_HERE" # Name of the Smart Group to create or check (e.g., "Recovery Lock Not Enabled")
group_name_lock_enabled="GROUP_NAME_HERE" # Name of the Smart Group to create or check (e.g., "Recovery Lock Enabled")
site_ID="-1" # Site ID, -1 for all sites (default)
generate_random_password="true" # Set to "true" a random password will be generated, set to "false" to use the provided password
password="Jamf1234567" # Set Password for Recovery Lock, only used if generate_random_password is set to "false" or empty
mode="enable" # Set to enable or disable Recovery Lock

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

# Function to get group infos by name
get_group_info_disabled() {
	curl --silent --request GET \
		--url "$jamf_pro_url/api/v2/computer-groups/smart-groups?page=0&page-size=100&sort=id%3Aasc&filter=name==%22${group_name_lock_disabled// /%20}%22" \
		--header "Authorization: Bearer $access_token" \
		--header 'accept: application/json' \
		--header 'content-type: application/json'
}
get_group_info_enabled() {
	curl --silent --request GET \
		--url "$jamf_pro_url/api/v2/computer-groups/smart-groups?page=0&page-size=100&sort=id%3Aasc&filter=name==%22${group_name_lock_enabled// /%20}%22" \
		--header "Authorization: Bearer $access_token" \
		--header 'accept: application/json' \
		--header 'content-type: application/json'
}

# Function to create a random password
generate_random_password() {
	local length=28 # Length of the password
	local charset='A-Za-z0-9!@#$%^&*()_+'
	local password=$(cat /dev/urandom | tr -dc "$charset" | fold -w "$length" | head -n 1)
	echo "$password"
}

# Function to create the recovery lock disabled group
create_recovery_lock_disabled_group() {
	## Creating the recovery lock disabled smart group if it does not exist
	# Check if group name is set else use default
	if [[ -z "$group_name_lock_disabled" ]]; then
		echo "No group name provided for 'Lock Disabled'. Using Smart Group'Recover_Lock_Manager: Recovery_Lock_disabled'."
		group_name_lock_disabled="Recover_Lock_Manager: Recovery_Lock_disabled"
	fi

	# Check if group already exists
	disabled_group=$(get_group_info_disabled)
	#echo "DEBUG: $disabled_group"

	if [[ $(echo "$disabled_group" | jq -r '.results | length') -gt 0 ]]; then
		group_id=$(echo "$disabled_group" | jq -r '.results[0].id')
		echo "The Smart Computer Group '$group_name_lock_disabled' with ID '$group_id' already exists. Recalculating the Smart Computer Group '$group_name_lock_disabled'..."
		echo ""
		# recalculate the smart group
		curl --request POST \
			--silent \
			--url "$jamf_pro_url/api/v1/smart-computer-groups/$group_id/recalculate" \
			--header "Authorization: Bearer $access_token" \
			--header 'accept: application/json' \
			--output /dev/null
	else
		echo "Creating smart group '$group_name_lock_disabled'..."
		create_response=$(curl --silent --request POST \
			--url "$jamf_pro_url/api/v2/computer-groups/smart-groups" \
			--header "Authorization: Bearer $access_token" \
			--header 'accept: application/json' \
			--header 'content-type: application/json' \
			--data "{
				\"name\": \"${group_name_lock_disabled}\",
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
		# echo "DEBUG (create): $create_response"
		# Check again if group exists
		disabled_group=$(get_group_info_disabled)
		if [[ $(echo "$disabled_group" | jq -r '.results | length') -gt 0 ]]; then
			group_id=$(echo "$disabled_group" | jq -r '.results[0].id')
			echo "Successfully create the Smart Computer Group: Name: '$group_name_lock_disabled' ID: '$group_id'. Proceeding..."
			echo ""
		else
			echo "Failed to create smart group '$group_name_lock_disabled'."
			exit 1
		fi
	fi
}

# Function to create the recovery lock enabled group
create_recovery_lock_enabled_group() {
	## Creating the recovery lock enabled smart group if it does not exist
	# Check if group name is set else use default
	if [[ -z "$group_name_lock_enabled" ]]; then
		echo "No group name provided for 'Lock Enabled'. Using Smart Group 'Recover_Lock_Manager: Recovery_Lock_Enabled'."
		group_name_lock_enabled="Recover_Lock_Manager: Recovery_Lock_Enabled"
	fi

	# Check if group exists
	enabled_group=$(get_group_info_enabled)
	#echo "DEBUG: $enabled_group"

	if [[ $(echo "$enabled_group" | jq -r '.results | length') -gt 0 ]]; then
		group_id=$(echo "$enabled_group" | jq -r '.results[0].id')
		echo "The Smart Computer Group '$group_name_lock_enabled' with ID '$group_id' already exists. Recalculating the Smart Computer Group '$group_name_lock_enabled'..."
		echo ""
		# recalculate the smart group
		curl --silent --request POST \
			--url "$jamf_pro_url/api/v1/smart-computer-groups/$group_id/recalculate" \
			--header "Authorization: Bearer $access_token" \
			--header 'accept: application/json' \
			--output /dev/null
	else
		echo "Creating smart group '$group_name_lock_enabled'..."
		create_response=$(curl --silent --request POST \
			--url "$jamf_pro_url/api/v2/computer-groups/smart-groups" \
			--header "Authorization: Bearer $access_token" \
			--header 'accept: application/json' \
			--header 'content-type: application/json' \
			--data "{
				\"name\": \"${group_name_lock_enabled}\",
				\"criteria\": [
					{
						\"name\": \"Recovery Lock Enabled\",
						\"value\": \"Enabled\",
						\"searchType\": \"is\",
						\"andOr\": \"and\"
					}
				],
				\"siteId\": \"$site_ID\"
			}")
		# echo "DEBUG (create): $create_response"
		# Check again if group exists
		enabled_group=$(get_group_info_enabled)
		if [[ $(echo "$enabled_group" | jq -r '.results | length') -gt 0 ]]; then
			group_id=$(echo "$enabled_group" | jq -r '.results[0].id')
			echo "Successfully create the Smart Computer Group: Name: '$group_name_lock_enabled' ID: '$group_id'. Proceeding..."
			echo ""
		else
			echo "Failed to create smart group '$group_name_lock_enabled'."
			exit 1
		fi
	fi
}

###### End Functions #####


#### Main Script Execution #####
# check / get access token
echo "#### Checking / retrieving access token ####"
checkTokenExpiration

# BEGIN API COMMANDS #


echo "#### Authentication successful. proceeding with API commands ####"
echo ""

# If mode is set to enable generate check for or generate password and create groups
if [[ "$mode" == "enable" ]]; then
	# Check if generate_random_password is set to true or empty, if yes generate a random password
	if [[ "$generate_random_password" == "true" ]]; then
		echo "Requested random password. Generating a random password for Recovery Lock..."
		recovery_password=$(generate_random_password)
		echo "Generated Recovery Lock Password."
		# creating group
		create_recovery_lock_disabled_group

	elif [[ "$generate_random_password" != "true" && -z "$password" ]]; then
		echo "No random password requested and no provided password found. A password is required!! Falling back to generating a random password for Recovery Lock..."
		recovery_password=$(generate_random_password)
		echo "Generated Recovery Lock Password."
		# creating group
		create_recovery_lock_disabled_group
	else
		recovery_password=${password}
		echo "Using the provided Recovery Lock Password."
		# creating group
		create_recovery_lock_disabled_group
	fi
else
	echo "Mode is set to disable Recovery Lock. No password will be generated or used."
	recovery_password=""
	create_recovery_lock_enabled_group
fi


# Get members of Smart Computer Group
group_members=$(curl --request GET \
	--url "$jamf_pro_url/api/v2/computer-groups/smart-group-membership/$group_id" \
	--silent \
	--header 'accept: application/json' \
	--header "Authorization: Bearer ${access_token}")

# If there are no group members exit
if [[ $(echo "$group_members" | jq -r '.members | length') -eq 0 ]]; then
	echo "No group members found. Exiting."
	exit 0
fi

# echo "DEBUG $group_members"

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
	#echo "DEBUG: RECOVERY LOCK PASSWORD: $recovery_password"
	# if mode is set to 'enable', print Setting Recovery Lock, else print disabling recovery lock
	if [[ "$mode" == "enable" ]]; then
		echo "Setting Recovery Lock for Management ID: $managementId"
	else
		echo "Disabling Recovery Lock for Management ID: $managementId"
	fi
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
			\"newPassword\": \"$recovery_password\"
		}
	}")

	echo "Response code: $response"
	if [[ "$response" -eq 201 ]]; then
		if [[ $mode == "enable" ]]; then
			echo "Recovery Lock set successfully."
			# recalculate smart groups 
		else
			echo "Recovery Lock disabled successfully."
		fi
	else
		if [[ $mode == "enable" ]]; then
			echo "Failed to set Recovery Lock. Response code: $response"
		else
			echo "Failed to disable Recovery Lock. Response code: $response"
		fi
	fi
	echo "#################### Finished processing computer ID: $computer_id ####################"
	echo ""
done

	# END API COMMANDS #

echo ""
checkTokenExpiration
invalidateToken
