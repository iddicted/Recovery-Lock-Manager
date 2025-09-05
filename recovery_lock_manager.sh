#!/bin/sh --no-rcs

# Tool to set Recovery Lock on all computers in a specified Smart Group in Jamf Pro
# DESCRIPTION:
	# This Tool uses Swift Dialog to help enable or disable Recovery Lock.
	# This script creates a Smart Group in Jamf Pro that identifies computers where Recovery Lock is enabled / not enabled.
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
				# - Read Sites
		# 3. Ensure you have jq installed for JSON parsing. (preinstallaed with macOS Sequoia (version 15) and later)
#####
# by Raphael Eckersley
# Creation Date: 2023-10-30
# Version: 3.0
# Last Modified: 2024-09-05
# Special thanks to Laurent Pertois (https://github.com/laurentpertois) for help with the site selection feature, testing, and debugging.
#####


################################################################################
##### CONFIGURABLE VARIABLES #####
### Jamf Pro Server credentials ###
# Prompt for credentials: yes or no
prompt_for_credentials="no" # yes or no

# Load Jamf Pro credentials from environment variables
# If prompt_for_credentials is set to "yes", the script will prompt for credentials using Swift Dialog
# If set to "no", it will use the values set in the environment variables below
# include them in your shell profile (.zprofile, .bash_profile, etc.)
jamf_pro_url="${JAMF_PRO_URL}" # Set JAMF_PRO_URL in your environment
client_id="${JAMF_CLIENT_ID}"  # Set JAMF_CLIENT_ID in your environment
client_secret="${JAMF_CLIENT_SECRET}" # Set JAMF_CLIENT_SECRET in your environment
#################################

### Swift Dialog variables ###
# Path to Swift Dialog binary
messageFont="size=20,name=HelveticaNeue"
titleFont="weight=bold,size=30,name=HelveticaNeue-Bold"
icon="https://github.com/iddicted/Recovery-Lock-Enabler/blob/main/Images/rlockenabler.png?raw=true"
#### End Configuration Variables ####
################################################################################


################################################################################
#### LOGGING SETUP (sh compatible) ####
LOG_DIR="$HOME/Library/Logs/RecoveryLockManager"
LOG_FILE="$LOG_DIR/RecoveryLockManager_$(date +'%Y-%m-%d_%H-%M-%S').log"
mkdir -p "$LOG_DIR" # Create the Log directory if it doesn't exist
# Create a temporary named pipe (a special type of file)
# and ensure it gets cleaned up when the script exits.
TMP_DIR=$(mktemp -d)
PIPE="$TMP_DIR/logpipe"
mkfifo "$PIPE"
trap 'rm -rf "$TMP_DIR"' EXIT
# Start a tee process in the background to read from the pipe
# and send output to the log file.
tee -a "$LOG_FILE" < "$PIPE" &
# Redirect all script output (stdout and stderr) to the pipe.
# The background tee process will catch it and do its job.
exec > "$PIPE" 2>&1
echo "############ Starting Recovery Lock Manager script ############"
echo "Logging output to: $LOG_FILE"
#### END LOGGING SETUP ####
################################################################################


#### SWIFT DIALOG  INSTALLATION ####


################################################################################ FUNCTIONS ################################################################################
#### API AUTHENTICATION ####
getAccessToken() {
    echo "INFO: Retrieving access token..."
	response=$(curl --silent --location --request POST "${jamf_pro_url}/api/oauth/token" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "client_id=${client_id}" \
        --data-urlencode "grant_type=client_credentials" \
        --data-urlencode "client_secret=${client_secret}")
    access_token=$(echo "$response" | jq -r '.access_token')
    token_expires_in=$(echo "$response" | jq -r '.expires_in')
    token_expiration_epoch=$(($current_epoch + $token_expires_in - 1))
	if [[ "$response" == *error* ]]; then
		echo "ERROR: Failed to retrieve access token or expiration time."
		exit 1
	fi
	echo "INFO: Access token retrieved successfully."
	echo "INFO: Token expires in: $token_expires_in seconds"
}
checkTokenExpiration() {
    current_epoch=$(date +%s)
    if [[ token_expiration_epoch -ge current_epoch ]]
    then
        echo "INFO: Token valid until the following epoch time: " "$token_expiration_epoch"
    else
        echo "INFO: No valid token available, getting new token"
        getAccessToken
    fi
}
invalidateToken() {
    echo "INFO: Invalidating access token..."
	responseCode=$(curl -w "%{http_code}" -H "Authorization: Bearer ${access_token}" $jamf_pro_url/api/v1/auth/invalidate-token -X POST -s -o /dev/null)
    if [[ ${responseCode} == 204 ]]
    then
        echo "INFO: Token successfully invalidated"
        access_token=""
        token_expiration_epoch="0"
    elif [[ ${responseCode} == 401 ]]
    then
        echo "INFO: Token already invalid"
    else
        echo "ERROR: An unknown error occurred invalidating the token"
    fi
}

########################
#### SWIFT DIALOG FUNCTIONS ####
# Function to check if Swift Dialog is installed, if not it downloads and installs it
install_swift_dialog() {
	echo "###### SWIFT DIALOG INSTALLATION ######"
	echo "Checking if SwiftDialog is installed"
	if [[ -e "/usr/local/bin/dialog" ]]; then
		echo "SwiftDialog is already installed"
	else
		echo "SwiftDialog Not installed, downloading and installing"
		/usr/bin/curl https://github.com/swiftDialog/swiftDialog/releases/download/v2.5.6/dialog-2.5.6-4805.pkg -L -o /tmp/dialog-2.5.6-4805.pkg
		cd /tmp
		sudo /usr/sbin/installer -pkg dialog-2.5.6-4805.pkg -target /
	fi
}
# Prompt to ask for credentials (Server URL, API Client and Secret)
credentialPrompt() {
	echo "INFO: Prompting user for Jamf Pro credentials..."
    # Request JSON output and use the correct syntax for textfield options
    serverDetails=$(/usr/local/bin/dialog \
        --title "Activation Lock Manager" \
        --message "Please enter your Jamf Pro details below:" \
        --textfield "Jamf Pro URL" --required \
        --textfield "Client ID" --required \
        --textfield "Client Secret" --required --secure \
        --icon "$icon" \
        --alignment "left" \
        --small \
        --button2 \
        --messagefont "$messageFont" \
        --titlefont "$titleFont" \
        --json)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        # Use jq to parse the JSON output
        jamf_pro_url=$(echo "$serverDetails" | jq -r '."Jamf Pro URL"')
        client_id=$(echo "$serverDetails" | jq -r '."Client ID"')
        client_secret=$(echo "$serverDetails" | jq -r '."Client Secret"')
    else
        echo "User cancelled"
        exit 0
    fi
    
    # Ensure the URL starts with https://
    if [[ $jamf_pro_url != "https://"* ]]; then 
        jamf_pro_url="https://$jamf_pro_url"
    fi
}
# Prompt asking for enabling or disabling Activation Lock
enable_disable_prompt() {
	echo "INFO: Prompting user for Activation Lock mode..."
	mode=$(/usr/local/bin/dialog \
		--title "Activation Lock Manager" \
		--message "Would you like to enable or disable Activation Lock on your Computers?" \
		--radio "groupSelection" \
		--selecttitle "Please select an option",radio --selectvalues "Enable, Disable" \
		--icon "$icon" \
		--alignment "left" \
		--button2 \
		--messagefont "$messageFont" \
		--titlefont "$titleFont" \
		--small)

		local exit_code=$?
		if [ $exit_code = 0 ];then
			# echo "DEBUG: Raw dialog output: $mode"
			mode=$(echo $mode | awk -F '"' '{print $4}')
			# echo "DEBUG: Parsed mode: $mode"
		else
			echo "User cancelled"
			exit 0
		fi
}
# Selection prompt for random password creation. Yes or No
create_random_password_prompt() {
	echo "INFO: Prompting user for password options..."
	generate_random_password=$(/usr/local/bin/dialog \
		--title "Activation Lock Manager" \
		--message "Should I create a random password for you?" \
		--radio "groupSelection" \
		--selecttitle "Please select an option",radio --selectvalues "Yes, I'll create my own" \
		--icon "$icon" \
		--alignment "left" \
		--button2 \
		--messagefont "$messageFont" \
		--titlefont "$titleFont" \
		--infotext "Random Password consists of:\n\n28 characters, upper & lower case letters, numbers, & symbols." \
		--small)

		local exit_code=$?
		if [ $exit_code = 0 ];then
			generate_random_password=$(echo $generate_random_password | awk -F '"' '{print $4}')
		else
			echo "User cancelled"
			exit 0
		fi
}
# Prompt for entering password
enter_password_prompt() {
	echo "INFO: Prompting user for password..."
	password=$(/usr/local/bin/dialog \
		--title "Activation Lock Manager" \
		--message "Please enter a password for Recovery Lock:" \
		--textfield "Password:",required,secure,prompt="ABC123" \
		--icon "$icon" \
		--alignment "left" \
		--button2 \
		--messagefont "$messageFont" \
		--titlefont "$titleFont" \
		--small)

		local exit_code=$?
		if [ $exit_code = 0 ];then
			password=$(echo $password |awk -F': : ' '{print $2}')
		else
			echo "INFO: User cancelled"
			exit 0
		fi
}
# Info screen that a random password has been generated
random_password_info() {
	generate_random_password=$(/usr/local/bin/dialog \
		--title "Activation Lock Manager" \
		--message "I have created a random Password for you. \n\nYou can view it in Jamf Pro." \
		--icon "$icon" \
		--alignment "left" \
		--button2 \
		--messagefont "$messageFont" \
		--titlefont "$titleFont" \
		--small)

		local exit_code=$?
		if [ $exit_code == 0 ];then
			generate_random_password=$(echo $generate_random_password | awk -F '"' '{print $2}')
		else
			echo "INFO: User cancelled"
			exit 0
		fi
}
# function to get all sites
# Thanks to Laurent Pertois (https://github.com/laurentpertois) for this feature and help with the code. 
select_site_prompt() {
	full_site_list=$(curl -s -X GET "${jamf_pro_url}/api/v1/sites" -H "accept: application/json" -H "Authorization: Bearer ${access_token}") # getting all sites
	#echo "DEBUG: Full site info: $full_site_list"
	listOfSites=$(echo "$full_site_list" | jq -r '. | map(.name) | join (", ")') # creating a comma-separated list of site names
	listOfSites="Full Jamf Pro, ---, $listOfSites" # adding "Full Jamf Pro" as the first option and a separator

	# Prompt user to select a site
	selectedSite=$(dialog \
		--title "Activation Lock Manager" \
		--message "Please select the site for the smart group:\n\nDefault: Full Jamf Pro" \
		--messagefont "$messageFont" \
        --titlefont "$titleFont" \
		--icon "$icon" \
		--button2 \
		--selecttitle "Select Site" --selectvalues "$listOfSites" --selectdefault "Full Jamf Pro"  | grep "SelectedOption" | awk -F ": " '{print $NF}' | sed 's/"//g')
	
	if [[ "$selectedSite" == "Full Jamf Pro" ]]; then # if user selected "Full Jamf Pro"
    	echo "INFO: INFO: User selected 'Full Jamf Pro' -> Using default site ID: -1"
		site_ID="-1"
	elif [[ "$selectedSite" == "" ]]; then # if clicked on cancel
		echo "INFO: User cancelled"
		exit 0
	else # if user selected a specific site
		site_ID=$(echo "$full_site_list" | jq -r --arg selectedSite "$selectedSite" '.[] | select (.name==$selectedSite) | .id')
		echo "INFO: User selected site: $selectedSite with ID: $site_ID"
	fi
}
# Prompt to enter name for Smart Group where Activation Lock is disabled
set_group_name_lock_disabled_prompt() {
	echo "INFO: Prompting user for Smart Group name..."
	local dialog_output
	# Prompt user for group name
	dialog_output=$(/usr/local/bin/dialog \
		--title "Activation Lock Manager" \
		--message "Enter the name for the Smart Group to create or use: \n\nIt will contain all Computers where Activation Lock is disabled.\n\n(Default: 'Recover Lock Manager: Recovery Lock Disabled')" \
		--textfield "Group Name:",required,prompt="Recovery Lock Disabled" \
		--icon "$icon" \
		--alignment "left" \
		--button2 \
		--messagefont "$messageFont" \
		--titlefont "$titleFont" \
		--infobuttontext "Use Default"\
		--small)

	local exit_code=$?
	# set -x
	#echo "DEBUG: dialog output: $dialog_output"
	if [ $exit_code = 0 ];then # if user clicked "OK"

		group_name_lock_disabled=$(echo "$dialog_output" | awk -F" : " '{ print $NF }')

	elif [ $exit_code = 3 ];then # if user clicked "Use Default"
		group_name_lock_disabled="Recover Lock Manager: Recovery Lock Disabled"
		echo "INFO: User selected default group name for 'Lock Disabled': $group_name_lock_disabled"
	else # if user clicked "Cancel"
		echo "INFO: User cancelled"
		exit 0
	fi
	# set +x
}
# Prompt to enter name for Smart Group where Activation Lock is enabled
set_group_name_lock_enabled_prompt() {
	echo "INFO: Prompting user for Smart Group name..."
	local dialog_output
	# Prompt user for group name
	dialog_output=$(/usr/local/bin/dialog \
		--title "Activation Lock Manager" \
		--message "Enter the name for the Smart Group to create or use: \n\nThis Group will contain all Computers where Activation Lock is enabled.\n\n(Default: 'Recover Lock Manager: Recovery Lock Enabled')" \
		--textfield "Group Name:",required,prompt="Recovery Lock Enabled" \
		--icon "$icon" \
		--alignment "left" \
        --button2 \
        --messagefont "$messageFont" \
        --titlefont "$titleFont" \
		--infobuttontext "Use Default" \
        --small)
    
	local exit_code=$?
	if [ $exit_code = 0 ];then # if user clicked "OK"
		group_name_lock_enabled=$(echo "$dialog_output" | awk -F': : ' '{print $2}')
		echo "INFO: User entered group name for 'Lock Enabled': $group_name_lock_enabled"
	elif [ $exit_code = 3 ];then # if user clicked "Use Default"
		group_name_lock_enabled="Recover Lock Manager: Recovery Lock Enabled"
		echo "INFO: User selected default group name for 'Lock Enabled': $group_name_lock_enabled"
	else # if user clicked "Cancel"
		echo "INFO: User cancelled"
		exit 0
	fi
}
# Prompt for displaying INFO: Number of group members found. Choose to continue
continue_prompt () {
	echo "INFO: Prompting user to continue..."
	# Get number of group members
	continue_choice=$(/usr/local/bin/dialog \
	--title "Activation Lock Manager" \
	--message "I have found $num_group_members computers in the selected Smart Group. \n\nWould you like to proceed?" \
	--icon "$icon" \
	--alignment "left" \
	--button1text "Continue" \
	--button2text "Cancel" \
	--messagefont "$messageFont" \
	--titlefont "$titleFont" \
	--small)

	local exit_code=$?
	if [ $exit_code = 0 ];then # if user clicked "Continue"
		echo "INFO: User chose to continue."
	else # if user clicked "Cancel"
		echo "INFO: User cancelled"
		exit 0
	fi
}
# Prompt to confirm action completion
donePrompt() {
	echo "INFO: API action completed. Setup Manager Workflow successful."
	# Prompt user that action is completed
	/usr/local/bin/dialog \
	--title "Activation Lock Manager" \
	--message "Action Completed. \n\nProcessed $num_group_members computers in the Smart Group '$group_name_lock_disabled'. \n\nPlease note that a reboot and Inventory update are required before the updated information will show in Jamf Pro" \
	--icon "$icon" \
	--alignment "left" \
	--small \
	--messagefont "$messageFont" \
	--titlefont "$titleFont" \
	--button1text "DONE" \
	--infobuttontext "Open Log" \
	--infobuttonaction "file://$LOG_FILE"
}
# dialog prompts to inform user that the group already exists. provide site name and ask to continue
enabled_group_exists_prompt () {
	echo "INFO: Prompting user to continue..."
	enabled_group_exists_choice=$(/usr/local/bin/dialog \
	--title "Activation Lock Manager" \
	--message "The Smart Group '$group_name_lock_enabled' already exists under the site '$group_site_name'. \n\nWould you like to use the group and continue?" \
	--icon "$icon" \
	--alignment "left" \
	--button1text "Continue" \
	--button2text "Cancel" \
	--messagefont "$messageFont" \
	--titlefont "$titleFont" \
	--small)

	local exit_code=$?
	if [ $exit_code = 0 ];then
		echo "INFO: User chose to continue."
	else
		echo "INFO: User cancelled"
		exit 0
	fi
}
disabled_group_exists_prompt () {
	echo "INFO: Prompting user to continue..."
	disabled_group_exists_choice=$(/usr/local/bin/dialog \
	--title "Activation Lock Manager" \
	--message "The Smart Group '$group_name_lock_disabled' already exists under the site '$group_site_name'. \n\nWould you like to use the group and continue?" \
	--icon "$icon" \
	--alignment "left" \
	--button1text "Continue" \
	--button2text "Cancel" \
	--messagefont "$messageFont" \
	--titlefont "$titleFont" \
	--small)

	local exit_code=$?
	if [ $exit_code = 0 ];then
		echo "INFO: User chose to continue."
	else
		echo "INFO: User cancelled"
		exit 0
	fi
}
no_members_in_disabled_group_prompt () {
	echo "INFO: Prompting user to continue..."
	no_members_choice=$(/usr/local/bin/dialog \
	--title "Activation Lock Manager" \
	--message "The Smart Group '$group_name_lock_disabled' has no members.\n\nClick 'OK' to exit." \
	--icon "$icon" \
	--alignment "left" \
	--button1text "OK" \
	--messagefont "$messageFont" \
	--titlefont "$titleFont" \
	--small)

	local exit_code=$?
	if [ $exit_code = 0 ];then
		echo "INFO: User chose to exit."
		exit 0
	fi
}
no_members_in_enabled_group_prompt () {
	echo "INFO: Prompting user to continue..."
	no_members_choice=$(/usr/local/bin/dialog \
	--title "Activation Lock Manager" \
	--message "The Smart Group '$group_name_lock_enabled' has no members.\n\nClick 'OK' to exit." \
	--icon "$icon" \
	--alignment "left" \
	--button1text "OK" \
	--messagefont "$messageFont" \
	--titlefont "$titleFont" \
	--small)

	local exit_code=$?
	if [ $exit_code = 0 ];then
		echo "INFO: User chose to exit."
		exit 0
	fi
}
# dialog prompt to inform user that the group already exists. ask to continue
# group_exists_prompt () {
# 	echo "INFO: Prompting user to continue..."
# 	group_exists_choice=$(/usr/local/bin/dialog \
# 	--title "Activation Lock Manager" \
# 	--message "The Smart Group '$group_name_lock_disabled' already exists. \n\nWould you like to use the group and continue?" \
# 	--icon "$icon" \
# 	--alignment "left" \
# 	--button1text "Continue" \
# 	--button2text "Cancel" \
# 	--messagefont "$messageFont" \
# 	--titlefont "$titleFont" \
# 	--small)

# 	local exit_code=$?
# 	if [ $exit_code = 0 ];then
# 		echo "INFO: User chose to continue."
# 	else
# 		echo "INFO: User cancelled"
# 		exit 0
# 	fi
# }
# Creating the recovery lock enabled group
#### END OF SWIFT DIALOG FUNCTIONS ####
#######################################


#### API AND OTHER FUNCTIONS ####
#################################
# Get group information by name
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
# Creating a random password
generate_random_password() {
    echo "INFO: User requested a password. Generating a random password..."
	local length=28 # Length of the password
    local charset='A-Za-z0-9!@#$%^&*()_+'
    # FIX: Add LC_ALL=C to the tr command to prevent locale errors.
    local password=$(cat /dev/urandom | LC_ALL=C tr -dc "$charset" | fold -w "$length" | head -n 1)
    echo "$password"
}
# Creating the recovery lock disabled group if it does not exist, else recalculate it.
# If it exists, prompt user to continue or cancel
create_recovery_lock_disabled_group() {
	
	## Creating the recovery lock disabled smart group if it does not exist

	# Check if group already exists
	disabled_group=$(get_group_info_disabled)
	# echo "DEBUG: $disabled_group"
	# echo "HEX DUMP OF VARIABLE:" && echo -n "$disabled_group" | xxd


	if [[ $(jq -r '.results | length' <<< "$disabled_group") -gt 0 ]]; then # if group exists
		group_id=$(echo "$disabled_group" | jq -r '.results[0].id')
		echo "WARNING: The Smart Computer Group '$group_name_lock_disabled' with ID '$group_id' already exists. Recalculating the Smart Computer Group '$group_name_lock_disabled'..."
		echo ""

		# get site ID to which the group is assigned to
		group_site_ID=$(echo "$disabled_group" | jq -r '.results[0].siteId')
		if [[ "$group_site_ID" == "-1" ]]; then # if site ID is -1 it means "All Sites"
			echo "INFO: The Smart Computer Group '$group_name_lock_disabled' is assigned to 'Full Jamf Pro' (All Sites)."
			group_site_name="Full Jamf Pro"
		else # get name of site by searching for the ID
			group_site_name=$(echo "$full_site_list" | jq -r --arg group_site_id "$group_site_ID" '.[] | select (.id==$group_site_id) | .name')
			echo "INFO: The Smart Computer Group '$group_name_lock_disabled' is assigned to site: '$group_site_name' (ID: $group_site_ID)" # If site ID is -1 it means "All Sites"

		fi
		# recalculate the smart group
		curl --request POST \
			--silent \
			--url "$jamf_pro_url/api/v1/smart-computer-groups/$group_id/recalculate" \
			--header "Authorization: Bearer $access_token" \
			--header 'accept: application/json' \
			--output /dev/null
		# Skip creation since group already exists
		echo "INFO: Smart group already exists, skipping creation."
		disabled_group_exists_prompt
	else
		echo "INFO: Creating smart group '$group_name_lock_disabled'..."
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
		#echo "DEBUG (create): $create_response"
		# Check again if group exists
		disabled_group=$(get_group_info_disabled)
		if [[ $(jq -r '.results | length' <<< "$disabled_group") -gt 0 ]]; then
			group_id=$(echo "$disabled_group" | jq -r '.results[0].id')
			echo "SUCCESS: Successfully created the Smart Computer Group: Name: '$group_name_lock_disabled' ID: '$group_id'. Proceeding..."
			echo ""
		else
			echo "ERROR: Failed to create smart group '$group_name_lock_disabled'."
			exit 1
		fi
	fi
}
# Creating the recovery lock enabled group if it does not exist, else recalculate it.
# If it exists, prompt user to continue or cancel
create_recovery_lock_enabled_group() {
	## Creating the recovery lock enabled smart group if it does not exist
	# Check if group name is set else use default
	if [[ -z "$group_name_lock_enabled" ]]; then
		echo "INFO: No group name provided for 'Lock Enabled'. Using Smart Group 'Recover Lock Manager: Recovery Lock Enabled'."
		group_name_lock_enabled="Recover Lock Manager: Recovery Lock Enabled"
	fi

	# Check if group exists
	enabled_group=$(get_group_info_enabled)
	# echo "DEBUG: $enabled_group"
	# set -x
	if [[ $(echo "$enabled_group" | jq -r '.totalCount') -gt 0 ]]; then
		group_id=$(echo "$enabled_group" | jq -r '.results[0].id')
		echo "INFO: The Smart Computer Group '$group_name_lock_enabled' with ID '$group_id' already exists. Recalculating the Smart Computer Group '$group_name_lock_enabled'..."
		echo ""
		# get site ID to which the group is assigned to
		group_site_ID=$(echo "$enabled_group" | jq -r '.results[0].siteId')
		if [[ "$group_site_ID" == "-1" ]]; then # if site ID is -1 it means "All Sites"
			echo "INFO: The Smart Computer Group '$group_name_lock_enabled' is assigned to 'Full Jamf Pro' (All Sites)."
			group_site_name="Full Jamf Pro"
		else # get name of site by searching for the ID
			group_site_name=$(echo "$full_site_list" | jq -r --arg group_site_id "$group_site_ID" '.[] | select (.id==$group_site_id) | .name')
			echo "INFO: The Smart Computer Group '$group_name_lock_enabled' is assigned to site: '$group_site_name' (ID: $group_site_ID)" # If site ID is -1 it means "All Sites"

		fi

		# recalculate the smart group
		curl --silent --request POST \
			--url "$jamf_pro_url/api/v1/smart-computer-groups/$group_id/recalculate" \
			--header "Authorization: Bearer $access_token" \
			--header 'accept: application/json' \
			--output /dev/null
		# Skip creation since group already exists
		echo "INFO: Smart group already exists, skipping creation."
		enabled_group_exists_prompt
		
	else
		echo "INFO: Creating smart group '$group_name_lock_enabled'..."
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
		# echo "DEBUG (create  enabled group): $create_response"
		# Check again if group exists
		enabled_group=$(get_group_info_enabled)
		if [[ $(echo "$enabled_group" | jq -r '.results | length') -gt 0 ]]; then
			group_id=$(echo "$enabled_group" | jq -r '.results[0].id')
			echo "SUCCESS: Successfully created the Smart Computer Group: Name: '$group_name_lock_enabled' ID: '$group_id'. Proceeding..."
			echo ""
		else
			echo "ERROR: Failed to create smart group '$group_name_lock_enabled'."
			exit 1
		fi
	fi
	# set +x
}
#### END API AND OTHER FUNCTIONS ####
#####################################
################################################################################ END FUNCTIONS ################################################################################






################################################################################ MAIN SCRIPT EXECUTION ################################################################################

install_swift_dialog # Ensure Swift Dialog is installed
echo "###### Recovery Lock Manager Starting ######"
# Check if credentials prompt is enabled. If yes, prompt for credentials. If no, use environment variables.
# If environment variables are not set, prompt for credentials.
if [[ "$prompt_for_credentials" == "no" ]]; then
	if [[ -z "$jamf_pro_url" || -z "$client_id" || -z "$client_secret" ]]; then
		echo "INFO: Credentials not set in environment variables. Prompting user for credentials."
		credentialPrompt
	else
		echo "INFO: Credentials found in environment variables. Using those."
	fi
else
	echo "INFO: prompt_for_credentials is set to 'yes'. Prompting user for credentials."
	credentialPrompt
fi
checkTokenExpiration # check / get access token

# Prompt user for Activation Lock mode
enable_disable_prompt
echo "INFO: User selected Activation Lock mode: $mode"
# echo "DEBUG: About to check mode. Value is: '$mode'"
# echo "DEBUG: Length of mode: ${#mode}"
# echo "DEBUG: Mode in hex: $(echo -n "$mode" | xxd)"

## GROUP AND PASSWORD CREATION BASED ON SELECTED MODE
# Check if mode is set to enable or disable activation lock
if [[ "$mode" == "Enable" ]]; then # Enable mode
	echo "INFO: Mode is set to 'enable Recovery Lock'. Proceeding with password options..."
	create_random_password_prompt # Prompt for random password generation
	# If generate_random_password is set to "Yes" generate a random password
	if [[ "$generate_random_password" == "Yes" ]]; then
		echo "INFO: User opted for a random password. Generating..."
		recovery_password=$(generate_random_password)
		if [ $? -ne 0 ]; then
			echo "Failed to generate a random password. Exiting."
			exit 1
		fi
		echo "INFO: Generated Recovery Lock Password."
		#echo "DEBUG: Generated Recovery Lock Password: $recovery_password"
		random_password_info # Inform user that a random password has been generated
		echo "INFO: Using the generated password as Recovery Lock Password."
		select_site_prompt # Prompt user for Site ID

		set_group_name_lock_disabled_prompt # Prompt user for Smart Group name
		#echo "INFO: User selected group name: $group_name_lock_disabled"
		create_recovery_lock_disabled_group # Create the Smart Group
		
	elif [[ "$generate_random_password" == "I'll create my own" ]]; then # User opted to create their own password
		echo "INFO: User opted to create their own password. Prompting for password..."
		enter_password_prompt # Prompt user for password
		recovery_password="${password}" # Assign user-provided password to recovery_password
		# echo "DEBUG: User provided Recovery Lock Password: $recovery_password"
		echo "INFO: Using the provided password as Recovery Lock Password."
		select_site_prompt # Prompt user for Site ID
		set_group_name_lock_disabled_prompt # Prompt user for Smart Group name
		echo "INFO: User selected group name: $group_name_lock_disabled"
		create_recovery_lock_disabled_group # Create the Smart Group
	else
		echo "ERROR: No valid password option selected. Exiting."
		exit 1
	fi
else
	echo "INFO: Mode is set to 'disable Recovery Lock'. No password will be generated or used."
	recovery_password=""
	select_site_prompt # Prompt user for Site ID
	set_group_name_lock_enabled_prompt # Prompt user for Smart Group name
	create_recovery_lock_enabled_group # Create the Smart Group
fi

## CHECK GROUPS AND SEND API COMMANDS TO GROUP MEMBERS
# Get members of Smart Computer Group
group_members=$(curl --request GET \
	--url "$jamf_pro_url/api/v2/computer-groups/smart-group-membership/$group_id" \
	--silent \
	--header 'accept: application/json' \
	--header "Authorization: Bearer ${access_token}")

# If there are no group members exit
if [[ $(echo "$group_members" | jq -r '.members | length') -eq 0 ]]; then
	echo "WARNING: No group members found. Exiting."
	if [[ "$mode" == "enable" ]]; then
		no_members_in_disabled_group_prompt
	else
		no_members_in_enabled_group_prompt
	fi
fi
# echo "DEBUG $group_members"
# print amount of group members found and add to variable
num_group_members=$(echo "$group_members" | jq -r '.members | length')
echo "INFO: Number of group members found: $num_group_members"
continue_prompt
# extract computer IDs from the group members
computer_ids=$(echo "$group_members" | jq -r '.members[]')

# START PROCESSING COMPUTERS
# iterate through each computer ID

echo "###### Processing Computers in Smart Group '$group_name_lock_disabled' ######"
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
	# Send API command to set or disable Recovery Lock
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
	# Check if the command was successful and print message
	echo "Response code: $response"
	if [[ "$response" -eq 201 ]]; then # Command was successful
		if [[ $mode == "enable" ]]; then
			echo "Recovery Lock set successfully."
			# recalculate smart groups 
		else
			echo "Recovery Lock disabled successfully."
		fi
	else # Command failed
		if [[ $mode == "enable" ]]; then
			echo "Failed to set Recovery Lock. Response code: $response"
		else
			echo "Failed to disable Recovery Lock. Response code: $response"
		fi
	fi
	echo "#################### Finished processing computer ID: $computer_id ####################"
	echo ""
done

# print number of computers processed

## END PROCESSING COMPUTERS
donePrompt # Inform user that processing is complete
checkTokenExpiration
invalidateToken
